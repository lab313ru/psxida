/************************************************************************

CDDAData.cpp

Copyright (C) 2007 Virus
Copyright (C) 2002 mooby

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

************************************************************************/
#pragma warning(disable:4786)

#include "CDDAData.hpp"
#include "Preferences.hpp"

#include <portaudio.h>

using namespace std;

extern Preferences prefs;
extern std::string programName;

// this callback repeats one track over and over
int CDDACallbackRepeat( const void *inputBuffer, void *outputBuffer,
                     unsigned long framesPerBuffer, const PaStreamCallbackTimeInfo *timeinfo,
					 PaStreamCallbackFlags statusFlags, void *userData )
{
   unsigned int i;
/* Cast data passed through stream to our structure type. */
   PlayCDDAData* data = (PlayCDDAData*)userData;
   short* out = (short*)outputBuffer;
    
   data->theCD->seek(data->CDDAPos);
   short* buffer = (short*)data->theCD->getBuffer();
   
   buffer += data->frameOffset;

   double volume = data->volume;

      // buffer the data
   for( i=0; i<framesPerBuffer; i++ )
   {
    /* Stereo channels are interleaved. */
      *out++ = (short)(*buffer++ * volume);              /* left */
      *out++ = (short)(*buffer++ * volume);             /* right */
      data->frameOffset += 4;

         // at the end of a frame, get the next one
      if (data->frameOffset == bytesPerFrame)
      {
         data->CDDAPos += CDTime(0,0,1);

            // when at the end of this track, loop to the start
            // of this track
         if (data->CDDAPos == data->CDDAEnd)
         {
            data->CDDAPos = data->CDDAStart;
         }

         data->theCD->seek(data->CDDAPos);
         data->frameOffset = 0;
         buffer = (short*)data->theCD->getBuffer();
      }
   }
}

// this callback plays through one track once and stops
int CDDACallbackOneTrackStop( const void *inputBuffer, void *outputBuffer,
                     unsigned long framesPerBuffer, const PaStreamCallbackTimeInfo *timeinfo,
					 PaStreamCallbackFlags statusFlags, void *userData )
{
   unsigned int i;
/* Cast data passed through stream to our structure type. */
   PlayCDDAData* data = (PlayCDDAData*)userData;
   short* out = (short*)outputBuffer;
   short* buffer;

      // seek to the current CDDA read position
   if (!data->endOfTrack)
   {
      data->theCD->seek(data->CDDAPos);
      buffer = (short*)data->theCD->getBuffer();
   }
   else
   {
      buffer = (short*)data->nullAudio;
   }

   buffer += data->frameOffset;

   double volume = data->volume;

      // buffer the data
   for( i=0; i<framesPerBuffer; i++ )
   {
    /* Stereo channels are interleaved. */
      *out++ = (short)(*buffer++ * volume);              /* left */
      *out++ = (short)(*buffer++ * volume);             /* right */
      data->frameOffset += 4;

         // at the end of a frame, get the next one
      if (data->frameOffset == bytesPerFrame)
      {
         data->CDDAPos += CDTime(0,0,1);

            // when at the end of this track, use null audio
         if (data->CDDAPos == data->CDDAEnd)
         {
            data->endOfTrack = true;
            buffer = (short*)data->nullAudio;
            data->CDDAPos -= CDTime(0,0,1);
            data->frameOffset = 0;
         }
            // not at end of track, just do normal buffering
         else
         {
            data->theCD->seek(data->CDDAPos);
            data->frameOffset = 0;
            buffer = (short*)data->theCD->getBuffer();
         }
      }
   }
}

PlayCDDAData::PlayCDDAData(const std::vector<TrackInfo> ti, CDTime gapLength) 
   : stream(NULL), 
     frameOffset(0), theCD(NULL), trackList(ti), playing(false),
     endOfTrack(false), pregapLength(gapLength)
{
   memset(nullAudio, 0, sizeof(nullAudio));
   volume = atof(prefs.prefsMap[volumeString].c_str())/(double)100;
   if (volume < 0) volume = 0;
   else if (volume > 1) volume = 1;
}

// initialize the CDDA file data and initalize the audio stream
void PlayCDDAData::openFile(const std::string& file) 
{
   PaError err;
   std::string extension;
   theCD = FileInterfaceFactory(file, extension);
   theCD->setPregap(pregapLength, trackList[2].trackStart);
   err = Pa_Initialize();
   if( err != paNoError )
   {
      Exception e(string("PA Init error: ") + string(Pa_GetErrorText( err )));
      THROW(e);
   }
      // disable extra caching on the file interface
   theCD->setCacheMode(FileInterface::oldMode);
}
   
// start playing the data
int PlayCDDAData::play(const CDTime& startTime)
{
   CDTime localStartTime = startTime;
      // if play was called with the same time as the previous call,
      // dont restart it.  this fixes a problem with FPSE's play call.
      // of course, if play is called with a different track, 
      // stop playing the current stream.
   if (playing)
   {
      if (startTime == InitialTime)
      {
         return 0;
      }
      else
      {
         stop();
      }
   }

   InitialTime = startTime;

   // make sure there's a valid option chosen
   if ((prefs.prefsMap[repeatString] != repeatOneString) &&
       (prefs.prefsMap[repeatString] != repeatAllString) &&
       (prefs.prefsMap[repeatString] != playOneString))
   {
      prefs.prefsMap[repeatString] = repeatAllString;
      prefs.write();
   }

      // figure out which track to play to set the end time
   if ( (prefs.prefsMap[repeatString] == repeatOneString) ||
        (prefs.prefsMap[repeatString] == playOneString))
   {
      unsigned int i = 1;
      while ( (i < (trackList.size() - 1)) && (startTime > trackList[i].trackStart) )
      {
         i++;
      }
         // adjust the start time if it's blatantly off from the start time...
      if (localStartTime > trackList[i].trackStart)
      {
         if ( (localStartTime - trackList[i].trackStart) > CDTime(0,2,0))
         {
            localStartTime = trackList[i].trackStart;
         }
      }
      else
      {
         if ( (trackList[i].trackStart - localStartTime) > CDTime(0,2,0))
         {
            localStartTime = trackList[i].trackStart;
         }
      }
      CDDAStart = localStartTime;
      CDDAEnd = trackList[i].trackStart + trackList[i].trackLength;
   }

   else if (prefs.prefsMap[repeatString] == repeatAllString)
   {
      CDDAEnd = trackList[trackList.size() - 1].trackStart +
         trackList[trackList.size() - 1].trackLength;
      CDDAStart = trackList[2].trackStart;
      if (localStartTime > CDDAEnd)
      {
         localStartTime = CDDAStart;
      }
   }

         // set the cdda position, start and end times
   CDDAPos = localStartTime;

   endOfTrack = false;

      // open a stream - pass in this CDDA object as the user data.
      // depending on the play mode, use a different callback
   PaError err;
   
   if (prefs.prefsMap[repeatString] == repeatAllString)
      err = Pa_OpenDefaultStream(&stream, 0, 2, paInt16, 44100, 5880, 
                                 CDDACallbackRepeat, this);
   else if (prefs.prefsMap[repeatString] == repeatOneString)
      err = Pa_OpenDefaultStream(&stream, 0, 2, paInt16, 44100, 5880, 
                                 CDDACallbackRepeat, this);
   else if (prefs.prefsMap[repeatString] == playOneString)
      err = Pa_OpenDefaultStream(&stream, 0, 2, paInt16, 44100, 5880, 
                                 CDDACallbackOneTrackStop, this);

   if( err != paNoError )
   {
     return 0;
   }
  
      // start the stream.  the CDDACallback will automatically get 
      // called to buffer the audio
   err = Pa_StartStream( stream );

   if( err != paNoError )
   {
     return 0;
   }

   playing = true;
   return 0;
}

// close the stream - nice and simple
int PlayCDDAData::stop()
{
   if (playing)
   {
      PaError err = Pa_CloseStream( stream );
      if( err != paNoError )
      {  
         Exception e(string("PA Close Stream error: ") + string(Pa_GetErrorText( err )));
         THROW(e);
      }
      playing = false;
   }
   return 0;
}

