#include <hexrays.hpp>
#include <ProtoAnalyzer.hpp>


plugmod_t* idaapi init(void)
{
  return PLUGIN_KEEP;
}

void idaapi term(void)
{
  return;
}

static bool Initialized = false;
static std::vector<ea_t> matched_pbcmds;

bool idaapi run(size_t) {
  if (!Initialized) {
    Initialized = true;
    add_proto_c_struct_to_local_types();
  }
  if (handled_results.empty()) {
    matched_pbcmds = search_pbcmd_by_magic();
    hadnle_matchs(matched_pbcmds);
  }
  int i = 1;
  for (auto result : handled_results) {
    msg("%s", result.c_str());
  }

  return true;
}

static char comment[] = "It's a simple plugin to improve experience!";
static char help[] = "";
static char wanted_name[] = "ida_proto_c_analyzer";
static char wanted_hotkey[] = "";

plugin_t PLUGIN =
{
  //version
  IDP_INTERFACE_VERSION,
  //flag
  0,
  //init func
  init,
  //term func
  term,
  //run func
  run,
  //description
  ///< Long comment about the plugin.
  ///< it could appear in the status line
  ///< or as a hint
  comment,
  ///< Multiline help about the plugin
  help,
  ///< The preferred short name of the plugin
  wanted_name,
  ///< The preferred hotkey to run the plugin
  wanted_hotkey
};