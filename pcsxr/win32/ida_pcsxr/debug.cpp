#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

#include <ida.hpp>
#include <idd.hpp>
#include <diskio.hpp>

#include "debug.h"

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
	if (psx_thread != NULL)
	{
		qthread_join(psx_thread);
		qthread_free(psx_thread);
		qthread_kill(psx_thread);
		psx_thread = NULL;
	}

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

	int rc = WinMain(GetHInstance(), (HINSTANCE)NULL, cmdline, SW_NORMAL);

	debug_event_t ev;
	ev.eid = PROCESS_EXIT;
	ev.pid = 1;
	ev.handled = true;
	ev.exit_code = rc;

	g_events.enqueue(ev, IN_BACK);

	return rc;
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

static int idaapi psx_set_resume_mode(thid_t tid, resume_mode_t resmod)// Run one instruction in the thread
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

	DBG_FLAG_NOHOST | DBG_FLAG_HWDATBPT_ONE | DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_NOSTARTDIR | DBG_FLAG_NOPARAMETERS | DBG_FLAG_NOPASSWORD,
	register_classes,
	RC_GP,
	registers,
	qnumber(registers),

	0x1000,

	NULL,
	0,
	0,

	DBG_RESMOD_STEP_INTO | DBG_RESMOD_STEP_OVER,

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