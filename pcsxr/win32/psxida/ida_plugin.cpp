#define VERSION "1.0.0"
#define NAME "PsxIda"

#include <ida.hpp>
#include <dbg.hpp>
#include <loader.hpp>

extern debugger_t debugger;

static bool plugin_inited;

static void print_version()
{
	static const char format[] = NAME " debugger plugin v%s;\nAuthor: Dr. MefistO [Lab 313] <meffi@lab313.ru>.";
	info(format, VERSION);
	msg(format, VERSION);
}

// Initialize debugger plugin
static bool init_plugin(void)
{
	if (ph.id != PLFM_MIPS)
		return false;

	return true;
}

// Initialize debugger plugin
static int idaapi init(void)
{
	if (init_plugin())
	{
		dbg = &debugger;
		plugin_inited = true;

		print_version();
		return PLUGIN_KEEP;
	}
	return PLUGIN_SKIP;
}

// Terminate debugger plugin
static void idaapi term(void)
{
	if (plugin_inited)
	{
		//term_plugin();
		plugin_inited = false;
	}
}

// The plugin method - usually is not used for debugger plugins
static void idaapi run(int /*arg*/)
{

}

//--------------------------------------------------------------------------
char comment[] = NAME " debugger plugin by Dr. MefistO.";

char help[] =
NAME " debugger plugin by Dr. MefistO.\n"
"\n"
"This module lets you to debug PS1 games in IDA.\n";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC | PLUGIN_HIDE | PLUGIN_DBG, // plugin flags
	init, // initialize

	term, // terminate. this pointer may be NULL.

	run, // invoke plugin

	comment, // long comment about the plugin
	// it could appear in the status line
	// or as a hint

	help, // multiline help about the plugin

	NAME " debugger plugin", // the preferred short name of the plugin

	"" // the preferred hotkey to run the plugin
};
