#include <ida.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <segment.hpp>
#include <diskio.hpp>

#include "ida_debug.h"

#include "psxcommon.h"
#include "r3000a.h"
#include "debug.h"
#include "psxmem.h"
#include "Win32.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);

struct breakpoint_s;
typedef breakpoint_s breakpoint_t;

extern void delete_breakpoint(breakpoint_t * bp);
extern breakpoint_t *find_breakpoint_by_addr(u32 address);
extern int add_breakpoint(int type, u32 address);

ea_t boot_address;
eventlist_t g_events;
qthread_t psx_thread = NULL;

static const char *register_classes[] =
{
	"General Purpose Registers",
	//"Coprocessor0 Registers",
	//"Cop2 data registers",
	//"Cop2 control registers",
	NULL,
};

#define RC_GP        1
#define RC_COP0      2
#define RC_COP2_DATA 4
#define RC_COP2_CTRL 8

register_info_t registers[] =
{
	/*
	r0, at, v0, v1, a0, a1, a2, a3,
	t0, t1, t2, t3, t4, t5, t6, t7,
	s0, s1, s2, s3, s4, s5, s6, s7,
	t8, t9, k0, k1, gp, sp, s8, ra;
	*/

	{ disRNameGPR[0x00], REGISTER_READONLY, RC_GP, dt_dword, NULL, 0 },

	{ disRNameGPR[0x01], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ disRNameGPR[0x02], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x03], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ disRNameGPR[0x04], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x05], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x06], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x07], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ disRNameGPR[0x08], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x09], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x0A], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x0B], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x0C], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x0D], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x0E], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x0F], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ disRNameGPR[0x10], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x11], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x12], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x13], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x14], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x15], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x16], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x17], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ disRNameGPR[0x18], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x19], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ disRNameGPR[0x1A], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x1B], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ disRNameGPR[0x1C], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x1D], REGISTER_ADDRESS | REGISTER_SP, RC_GP, dt_dword, NULL, 0 },
	{ disRNameGPR[0x1E], REGISTER_ADDRESS | REGISTER_FP, RC_GP, dt_dword, NULL, 0 },
	
	{ disRNameGPR[0x1F], REGISTER_ADDRESS, RC_GP, dt_dword, NULL, 0 },

	{ "PC", REGISTER_ADDRESS | REGISTER_IP, RC_GP, dt_dword, NULL, 0 },

};

// Initialize debugger
// Returns true-success
// This function is called from the main thread
static bool idaapi init_debugger(const char *hostname, int portnum, const char *password)
{
	return true;
}

// Terminate debugger
// Returns true-success
// This function is called from the main thread
static bool idaapi term_debugger(void)
{
	return true;
}

// Return information about the n-th "compatible" running process.
// If n is 0, the processes list is reinitialized.
// 1-ok, 0-failed, -1-network error
// This function is called from the main thread
static int idaapi process_get_info(int n, process_info_t *info)
{
	return 0;
}

HINSTANCE GetHInstance()
{
	MEMORY_BASIC_INFORMATION mbi;
	SetLastError(ERROR_SUCCESS);
	VirtualQuery(GetHInstance, &mbi, sizeof(mbi));

	return (HINSTANCE)mbi.AllocationBase;
}
char cmdline[2048];
static int idaapi psx_process(void *ud)
{
	SetCurrentDirectoryA(idadir("plugins"));

	WinMain(GetHInstance(), (HINSTANCE)NULL, cmdline, SW_NORMAL);

	return 0;
}

static void term_psx_process()
{
	if (psx_thread != NULL)
	{
		qthread_join(psx_thread);
		qthread_free(psx_thread);
		qthread_kill(psx_thread);
		psx_thread = NULL;
	}
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
	qsnprintf(cmdline, sizeof(cmdline), "%s", args);

	psx_thread = qthread_create(psx_process, NULL);

	boot_address = inf.startIP;

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
	PauseDebugger();
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
	ResumeDebugger();
	if (Running) ClosePlugins();

	SysClose();
	SaveConfig();

	term_psx_process();
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
	switch (event->eid)
	{
	case PROCESS_SUSPEND:
	case BREAKPOINT:
	case STEP:
		switch (get_running_notification())
		{
		case dbg_null:
			ResumeDebugger();
			break;
		}
		break;
	case PROCESS_EXIT:
		term_psx_process();
		break;
	}
	
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

static int idaapi psx_set_resume_mode(thid_t tid, resume_mode_t resmod)// Run one instruction in the thread
{
	switch (resmod)
	{
	case RESMOD_INTO:
	{
		extern int trace;
		extern int paused;

		trace = 1;
		paused = 0;
	} break;
	}

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
	if (clsmask & RC_GP)
	{
		for (int i = 0; i < 32; ++i)
		{
			values[i].ival = (u32)(psxRegs.GPR.r[i]);
		}
		values[32].ival = (u32)psxRegs.pc;
	}

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
	if (regidx >= 0 && regidx < 32)
	{
		psxRegs.GPR.r[regidx] = (u32)(value->ival);
	}
	psxRegs.pc = (u32)(value->ival);

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
	static bool first_run = true;

	if (first_run)
	{
		first_run = false;
		return -2;
	}

	/*  Playstation Memory Map (from Playstation doc by Joshua Walker)
	0x0000_0000-0x0000_ffff		Kernel (64K)
	0x0001_0000-0x001f_ffff		User Memory (1.9 Meg)

	0x1f00_0000-0x1f00_ffff		Parallel Port (64K)

	0x1f80_0000-0x1f80_03ff		Scratch Pad (1024 bytes)

	0x1f80_1000-0x1f80_2fff		Hardware Registers (8K)

	0x1fc0_0000-0x1fc7_ffff		BIOS (512K)

	0x8000_0000-0x801f_ffff		Kernel and User Memory Mirror (2 Meg) Cached
	0x9fc0_0000-0x9fc7_ffff		BIOS Mirror (512K) Cached

	0xa000_0000-0xa01f_ffff		Kernel and User Memory Mirror (2 Meg) Uncached
	0xbfc0_0000-0xbfc7_ffff		BIOS Mirror (512K) Uncached
	*/
	memory_info_t *mi = &areas.push_back();
	mi->startEA = 0x00000000;
	mi->endEA =   0x00010000;
	mi->name = "KERNEL";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	mi = &areas.push_back();
	mi->startEA = 0x00010000;
	mi->endEA =   0x00200000;
	mi->name = "USER_RAM";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	mi = &areas.push_back();
	mi->startEA = 0x1F000000;
	mi->endEA =   0x1F010000;
	mi->name = "PARALLEL_PORT";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	mi = &areas.push_back();
	mi->startEA = 0x1F800000;
	mi->endEA =   0x1F800400;
	mi->name = "SCRATCH_PAD";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	mi = &areas.push_back();
	mi->startEA = 0x1F801000;
	mi->endEA =   0x1F803000;
	mi->name = "HW_REGS";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	mi = &areas.push_back();
	mi->startEA = 0x1FC00000;
	mi->endEA =   0x1FC80000;
	mi->name = "BIOS";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	mi = &areas.push_back();
	mi->startEA = 0x1FC00000;
	mi->endEA =   0x1FC80000;
	mi->name = "BIOS";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	// Mirror KSEG0
	mi = &areas.push_back();
	mi->startEA = 0x80000000;
	mi->endEA =   0x80010000;
	mi->name = "KERNEL";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	mi = &areas.push_back();
	mi->startEA = 0x80010000;
	mi->endEA =   0x80200000;
	mi->name = "USER_RAM";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	mi = &areas.push_back();
	mi->startEA = 0x9FC00000;
	mi->endEA =   0x9FC80000;
	mi->name = "BIOS";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	// Mirror KSEG1
	mi = &areas.push_back();
	mi->startEA = 0xA0000000;
	mi->endEA =   0xA0010000;
	mi->name = "KERNEL";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	mi = &areas.push_back();
	mi->startEA = 0xA0010000;
	mi->endEA =   0xA0200000;
	mi->name = "USER_RAM";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	mi = &areas.push_back();
	mi->startEA = 0xBFC00000;
	mi->endEA =   0xBFC80000;
	mi->name = "BIOS";
	mi->bitness = 1; // 32-bit
	mi->perm = SEGPERM_MAXVAL;
	mi->sbase = 0;

	return 1;
}

// Read process memory
// Returns number of read bytes
// 0 means read error
// -1 means that the process does not exist anymore
// This function is called from debthread
static ssize_t idaapi read_memory(ea_t ea, void *buffer, size_t size)
{
	for (size_t i = 0; i < size; ++i)
	{
		((u8 *)buffer)[i] = psxMemRead8(ea + i);
	}

	return size;
}

// Write process memory
// Returns number of written bytes, -1-fatal error
// This function is called from debthread
static ssize_t idaapi write_memory(ea_t ea, const void *buffer, size_t size)
{
	for (size_t i = 0; i < size; ++i)
	{
		psxMemWrite8(ea + i, ((u8 *)buffer)[i]);
	}

	return size;
}

// Is it possible to set breakpoint?
// Returns: BPT_...
// This function is called from debthread or from the main thread if debthread
// is not running yet.
// It is called to verify hardware breakpoints.
static int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
	switch (type)
	{
	case BPT_READ:
	case BPT_WRITE:
	case BPT_RDWR:
		if (
			(len != 1 && len != 2 && len != 4)
			)
			return BPT_BAD_LEN;
		if (
			((ea & 1) != 0) &&
			(len == 2)
			)
			return BPT_BAD_ALIGN;
		if (
			((ea & 3) != 0) &&
			(len == 4)
			)
			return BPT_BAD_ALIGN;
		if (
			(len == 4)
			)
			return BPT_BAD_ALIGN;
		break;
	}

	return BPT_OK;
}

// Add/del breakpoints.
// bpts array contains nadd bpts to add, followed by ndel bpts to del.
// returns number of successfully modified bpts, -1-network error
// This function is called from debthread
static int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
	for (int i = 0; i < nadd; ++i)
	{
		switch (bpts[i].type)
		{
		case BPT_EXEC:
			add_breakpoint(BE, bpts[i].ea);
			break;
		case BPT_READ:
			switch (bpts[i].size)
			{
			case 1:
				add_breakpoint(BR1, bpts[i].ea);
				break;
			case 2:
				add_breakpoint(BR2, bpts[i].ea);
				break;
			case 4:
				add_breakpoint(BR4, bpts[i].ea);
				break;
			}
			break;
		case BPT_WRITE:
			switch (bpts[i].size)
			{
			case 1:
				add_breakpoint(BW1, bpts[i].ea);
				break;
			case 2:
				add_breakpoint(BW2, bpts[i].ea);
				break;
			case 4:
				add_breakpoint(BW4, bpts[i].ea);
				break;
			}
			break;
		case BPT_RDWR:
			switch (bpts[i].size)
			{
			case 1:
				add_breakpoint(BR1, bpts[i].ea);
				add_breakpoint(BW1, bpts[i].ea);
				break;
			case 2:
				add_breakpoint(BR2, bpts[i].ea);
				add_breakpoint(BW2, bpts[i].ea);
				break;
			case 4:
				add_breakpoint(BR4, bpts[i].ea);
				add_breakpoint(BW4, bpts[i].ea);
				break;
			}
			break;
		}
	}

	for (int i = nadd; i < nadd + ndel; ++i)
	{
		breakpoint_t *bp;

		if ((bp = find_breakpoint_by_addr((u32)(bpts[i].ea))))
		{
			delete_breakpoint(bp);
		}
	}

	return (nadd + ndel);
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

	DBG_FLAG_NOHOST | DBG_FLAG_HWDATBPT_ONE | DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_NOSTARTDIR | DBG_FLAG_NOPARAMETERS | DBG_FLAG_NOPASSWORD | DBG_FLAG_DEBTHREAD,
	register_classes,
	RC_GP,
	registers,
	qnumber(registers),

	0x1000,

	NULL,
	0,
	0,

	DBG_RESMOD_STEP_INTO /*| DBG_RESMOD_STEP_OVER*/,

	init_debugger,
	term_debugger,

	process_get_info,

	start_process,
	NULL,
	NULL,

	rebase_if_required_to,
	prepare_to_pause_process,
	psx_exit_process,

	get_debug_event,
	continue_after_event,

	NULL,
	stopped_at_debug_event,

	thread_suspend,
	thread_continue,
	psx_set_resume_mode,

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

	NULL,
};