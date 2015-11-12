#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <winsock.h>

#include <ida.hpp>
#include <idd.hpp>

#include "debug.h"

eventlist_t g_events;
SOCKET g_sock = NULL;

static const char *register_classes[] =
{
	"General Purpose Registers",
	"Coprocessor0 Registers",
	"Cop2 data registers",
	"Cop2 control registers",
	NULL,
};

#define RC_GP        1
#define RC_COP0      2
#define RC_COP2_DATA 4
#define RC_COP2_CTRL 8

const char *fmt_SVector3D[] =
{
	"SVector3D",

	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",

	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",

	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
};

const char *fmt_SVector2D[] =
{
	"SVector2D",

	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",
	"x",

	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
	"y",
};

const char *fmt_SVector2Dz[] =
{
	"SVector2Dz",

	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
	"z",
};

const char *fmt_CBGR[] =
{
	"CBGR",

	"r",
	"r",
	"r",
	"r",
	"r",
	"r",
	"r",
	"r",

	"g",
	"g",
	"g",
	"g",
	"g",
	"g",
	"g",
	"g",

	"b",
	"b",
	"b",
	"b",
	"b",
	"b",
	"b",
	"b",

	"c",
	"c",
	"c",
	"c",
	"c",
	"c",
	"c",
	"c",
};

register_info_t registers[] =
{
	/*
	r0, at, v0, v1, a0, a1, a2, a3,
	t0, t1, t2, t3, t4, t5, t6, t7,
	s0, s1, s2, s3, s4, s5, s6, s7,
	t8, t9, k0, k1, gp, sp, s8, ra, lo, hi;
	*/

	{ "r0", REGISTER_READONLY, RC_GP, dt_dword, NULL, 0 },

	{ "at", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ "v0", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "v1", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ "a0", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "a1", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "a2", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "a3", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ "t0", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "t1", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "t2", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "t3", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "t4", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "t5", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "t6", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "t7", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ "s0", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "s1", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "s2", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "s3", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "s4", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "s5", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "s6", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "s7", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ "t8", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "t9", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ "k0", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "k1", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ "gp", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ "sp", REGISTER_ADDRESS | REGISTER_SP, RC_GP, dt_dword, NULL, 0 },
	{ "fp", REGISTER_ADDRESS | REGISTER_FP, RC_GP, dt_dword, NULL, 0 },
	
	{ "ra", REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ "PC", REGISTER_ADDRESS | REGISTER_IP, RC_GP, dt_dword, NULL, 0 },

	/*
	Index,     Random,    EntryLo0,  BPC,
	Context,   BDA,       PIDMask,   DCIC,
	BadVAddr,  BDAM,      EntryHi,   BPCM,
	Status,    Cause,     EPC,       PRid,
	Config,    LLAddr,    WatchLO,   WatchHI,
	XContext,  Reserved1, Reserved2, Reserved3,
	Reserved4, Reserved5, ECC,       CacheErr,
	TagLo,     TagHi,     ErrorEPC,  Reserved6
	*/

	{ "Index", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "Random", REGISTER_READONLY, RC_COP0, dt_dword, NULL, 0 },
	{ "EntryLo0", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "BPC", REGISTER_ADDRESS, RC_COP0, dt_dword, NULL, 0 },
	{ "Context", REGISTER_READONLY | REGISTER_ADDRESS, RC_COP0, dt_dword, NULL, 0 },
	{ "BDA", REGISTER_ADDRESS, RC_COP0, dt_dword, NULL, 0 },
	{ "PIDMask", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "DCIC", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "BadVAddr", REGISTER_ADDRESS, RC_COP0, dt_dword, NULL, 0 },
	{ "BDAM", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "EntryHi", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "BPCM", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "Status", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "Cause", REGISTER_READONLY, RC_COP0, dt_dword, NULL, 0 },
	{ "EPC", REGISTER_READONLY | REGISTER_ADDRESS, RC_COP0, dt_dword, NULL, 0 },
	{ "PRid", REGISTER_READONLY, RC_COP0, dt_dword, NULL, 0 },
	{ "Config", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "LLAddr", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "WatchLO", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "WatchHI", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "XContext", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "Reserved1", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "Reserved2", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "Reserved3", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "Reserved4", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "Reserved5", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "ECC", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "CacheErr", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "TagLo", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "TagHi", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "ErrorEPC", NULL, RC_COP0, dt_dword, NULL, 0 },
	{ "Reserved6", NULL, RC_COP0, dt_dword, NULL, 0 },

	/*
	SVector3D     v0, v1, v2;
	CBGR          rgb;
	s32          otz;
	s32          ir0, ir1, ir2, ir3;
	SVector2D     sxy0, sxy1, sxy2, sxyp;
	SVector2Dz    sz0, sz1, sz2, sz3;
	CBGR          rgb0, rgb1, rgb2;
	s32          reserved;
	s32          mac0, mac1, mac2, mac3;
	u32 irgb, orgb;
	s32          lzcs, lzcr;
	*/

	{ "v0", REGISTER_CUSTFMT, RC_COP2_DATA, dt_qword, fmt_SVector3D, 0 },
	{ "v1", REGISTER_CUSTFMT, RC_COP2_DATA, dt_qword, fmt_SVector3D, 0 },
	{ "v2", REGISTER_CUSTFMT, RC_COP2_DATA, dt_qword, fmt_SVector3D, 0 },

	{ "rgb", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_CBGR, 0 },

	{ "otz", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },

	{ "ir0", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },
	{ "ir1", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },
	{ "ir2", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },
	{ "ir3", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },

	{ "sxy0", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_SVector2D, 0 },
	{ "sxy1", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_SVector2D, 0 },
	{ "sxy2", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_SVector2D, 0 },
	{ "sxyp", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_SVector2D, 0 },

	{ "sz0", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_SVector2Dz, 0 },
	{ "sz1", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_SVector2Dz, 0 },
	{ "sz2", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_SVector2Dz, 0 },
	{ "sz3", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_SVector2Dz, 0 },

	{ "rgb0", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_CBGR, 0 },
	{ "rgb1", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_CBGR, 0 },
	{ "rgb2", REGISTER_CUSTFMT, RC_COP2_DATA, dt_dword, fmt_CBGR, 0 },

	{ "reserved", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },

	{ "mac0", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },
	{ "mac1", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },
	{ "mac2", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },
	{ "mac3", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },

	{ "irbg", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },
	{ "orgb", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },

	{ "lzcs", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },
	{ "lzcr", NULL, RC_COP2_DATA, dt_dword, NULL, 0 },
};

// Initialize debugger
// Returns true-success
// This function is called from the main thread
static bool idaapi init_debugger(const char *hostname, int portnum, const char *password)
{
	WSADATA wsaData;
	int wsaRes;
	sockaddr_in saddr;
	
	// Initialize Winsock
	wsaRes = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (wsaRes != 0) {
		error("WSAStartup error: %d\n", wsaRes);
		return false;
	}

	g_sock = socket(AF_INET, SOCK_STREAM, 0);

	if (g_sock == INVALID_SOCKET) {
		error("Socket error: %ld\n", WSAGetLastError());
		WSACleanup();
		return false;
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(portnum);
	saddr.sin_addr.s_addr = inet_addr(hostname);

	show_wait_box("Waiting for connection with PCSXR socket...");

	fd_set readSet;
	FD_ZERO(&readSet);
	FD_SET(g_sock, &readSet);

	while (true)
	{
		if (wasBreak())
			break;
		
		if (select(0, &readSet, NULL, NULL, NULL) > 0)
		{
			if (FD_ISSET(g_sock, &readSet))
			{
				return true;
			}
		}
		else
		{
			error("Connection error: %ld!", WSAGetLastError());
			closesocket(g_sock);
		}
	}

	return false;
}

// Terminate debugger
// Returns true-success
// This function is called from the main thread
static bool idaapi term_debugger(void)
{
	if (g_sock)
		closesocket(g_sock);

	g_sock = NULL;
	WSACleanup();

	return true;
}

// Return information about the n-th "compatible" running process.
// If n is 0, the processes list is reinitialized.
// 1-ok, 0-failed, -1-network error
// This function is called from the main thread
static int idaapi process_get_info(int n, process_info_t *info)
{
	return 1;
}

// Start an executable to debug
// 1 - ok, 0 - failed, -2 - file not found (ask for process options)
// 1|CRC32_MISMATCH - ok, but the input file crc does not match
// -1 - network error
// This function is called from debthread
static int idaapi start_process(const char *path,
	const char *args,
	const char *startdir,
	int dbg_proc_flags,
	const char *input_path,
	uint32 input_file_crc32)
{
	return 1;
}

// Attach to an existing running process
// 1-ok, 0-failed, -1-network error
// event_id should be equal to -1 if not attaching to a crashed process
// This function is called from debthread
static int idaapi psx_attach_process(pid_t pid, int event_id)
{
	return 1;
}

// Detach from the debugged process
// May be called while the process is running or suspended.
// Must detach from the process in any case.
// The kernel will repeatedly call get_debug_event() and until PROCESS_DETACH.
// In this mode, all other events will be automatically handled and process will be resumed.
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi psx_detach_process(void)
{
	return 1;
}

// rebase database if the debugged program has been rebased by the system
// This function is called from the main thread
static void idaapi rebase_if_required_to(ea_t new_base)
{

}

// Prepare to pause the process
// This function will prepare to pause the process
// Normally the next get_debug_event() will pause the process
// If the process is sleeping then the pause will not occur
// until the process wakes up. The interface should take care of
// this situation.
// If this function is absent, then it won't be possible to pause the program
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi prepare_to_pause_process(void)
{
	return 1;
}

// Stop the process.
// May be called while the process is running or suspended.
// Must terminate the process in any case.
// The kernel will repeatedly call get_debug_event() and until PROCESS_EXIT.
// In this mode, all other events will be automatically handled and process will be resumed.
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi psx_exit_process(void)
{
	return 1;
}

// Get a pending debug event and suspend the process
// This function will be called regularly by IDA.
// This function is called from debthread
static gdecode_t idaapi get_debug_event(debug_event_t *event, int timeout_ms)
{
	while (true)
	{
		// are there any pending events?
		if (g_events.retrieve(event))
		{
			return g_events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
		}
		if (g_events.empty())
			break;
	}
	return GDE_NO_EVENT;
}

// Continue after handling the event
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi continue_after_event(const debug_event_t *event)
{
	return 1;
}

// The following function will be called by the kernel each time
// when it has stopped the debugger process for some reason,
// refreshed the database and the screen.
// The debugger module may add information to the database if it wants.
// The reason for introducing this function is that when an event line
// LOAD_DLL happens, the database does not reflect the memory state yet
// and therefore we can't add information about the dll into the database
// in the get_debug_event() function.
// Only when the kernel has adjusted the database we can do it.
// Example: for imported PE DLLs we will add the exported function
// names to the database.
// This function pointer may be absent, i.e. NULL.
// This function is called from the main thread
static void idaapi stopped_at_debug_event(bool dlls_added)
{

}

// The following functions manipulate threads.
// 1-ok, 0-failed, -1-network error
// These functions are called from debthread
static int idaapi thread_suspend(thid_t tid) // Suspend a running thread
{
	return 1;
}

static int idaapi thread_continue(thid_t tid) // Resume a suspended thread
{
	return 1;
}

static int idaapi thread_set_step(thid_t tid) // Run one instruction in the thread
{
	return 1;
}

// Read thread registers
//    tid    - thread id
//    clsmask- bitmask of register classes to read
//    regval - pointer to vector of regvals for all registers
//             regval is assumed to have debugger_t::registers_size elements
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi read_registers(thid_t tid, int clsmask, regval_t *values)
{
	return 1;
}

// Write one thread register
//    tid    - thread id
//    regidx - register index
//    regval - new value of the register
// 1-ok, 0-failed, -1-network error
// This function is called from debthread
static int idaapi write_register(thid_t tid, int regidx, const regval_t *value)
{
	return 1;
}

//
// The following functions manipulate bytes in the memory.
//
// Get information on the memory areas
// The debugger module fills 'areas'. The returned vector MUST be sorted.
// Returns:
//   -3: use idb segmentation
//   -2: no changes
//   -1: the process does not exist anymore
//    0: failed
//    1: new memory layout is returned
// This function is called from debthread
static int idaapi get_memory_info(meminfo_vec_t &areas)
{
	return 1;
}

// Read process memory
// Returns number of read bytes
// 0 means read error
// -1 means that the process does not exist anymore
// This function is called from debthread
static ssize_t idaapi read_memory(ea_t ea, void *buffer, size_t size)
{
	return size;
}

// Write process memory
// Returns number of written bytes, -1-fatal error
// This function is called from debthread
static ssize_t idaapi write_memory(ea_t ea, const void *buffer, size_t size)
{
	return size;
}

// Is it possible to set breakpoint?
// Returns: BPT_...
// This function is called from debthread or from the main thread if debthread
// is not running yet.
// It is called to verify hardware breakpoints.
static int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
	return BPT_OK;
}

// Add/del breakpoints.
// bpts array contains nadd bpts to add, followed by ndel bpts to del.
// returns number of successfully modified bpts, -1-network error
// This function is called from debthread
static int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
	return (nadd + ndel);
}

// Map process address
// This function may be absent
//      off    - offset to map
//      regs   - current register values. if regs == NULL, then perform
//               global mapping, which is indepedent on used registers
//               usually such a mapping is a trivial identity mapping
//      regnum - required mapping. maybe specified as a segment register number
//               or a regular register number if the required mapping can be deduced
//               from it. for example, esp implies that ss should be used.
// Returns: mapped address or BADADDR
// This function is called from debthread
static ea_t idaapi map_address(ea_t off, const regval_t *regs, int regnum)
{
	return off;
}

//--------------------------------------------------------------------------
//
//	  DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

debugger_t debugger =
{
	IDD_INTERFACE_VERSION,
	"ida_pcsxr",
	456,
	"mipsrl",

	DBG_FLAG_REMOTE | DBG_FLAG_HWDATBPT_ONE | DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_NEEDPORT | DBG_FLAG_NOSTARTDIR | DBG_FLAG_NOPARAMETERS | DBG_FLAG_NOPASSWORD,
	register_classes,
	RC_GP,
	registers,
	qnumber(registers),

	0x1000,

	NULL,
	NULL,
	0,
	0,

	init_debugger,
	term_debugger,

	process_get_info,

	start_process,
	psx_attach_process,
	psx_detach_process,
	rebase_if_required_to,
	prepare_to_pause_process,
	psx_exit_process,

	get_debug_event,
	continue_after_event,

	NULL,
	stopped_at_debug_event,

	thread_suspend,
	thread_continue,
	thread_set_step,

	read_registers,
	write_register,

	NULL,

	get_memory_info,
	read_memory,
	write_memory,

	is_ok_bpt,
	update_bpts,
	NULL,

	NULL,
	NULL,
	NULL,

	map_address,
};