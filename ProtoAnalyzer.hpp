#pragma once
#include <unordered_map>
#include <vector>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <typeinf.hpp>

const char PBCFD[] = "struct ProtobufCFieldDescriptor { const char *name; uint32_t id; int label; int type; unsigned int quantifier_offset; unsigned int offset; const void *descriptor; const void *default_value; uint32_t flags; unsigned int reserved_flags; void *reserved2; void *reserved3; };";
const char PBCMD[] = "struct ProtobufCMessageDescriptor { uint32_t magic; const char *name; const char *short_name; const char *c_name; const char *package_name; size_t sizeof_message; unsigned int n_fields; const ProtobufCFieldDescriptor *fields; const unsigned int *fields_sorted_by_name; unsigned int n_field_ranges; char *field_ranges; __int64 message_init; void *reserved1; void *reserved2; void *reserved3; };";
const char PBMAGIC[] = { 0xF9, 0xEE, 0xAA, 0x28 };

tinfo_t pbcfd_tif;
tinfo_t pbcmd_tif;
void add_proto_c_struct_to_local_types()
{

  qstring name;
  if (!get_type_ordinal(nullptr, "ProtobufCFieldDescriptor")) {
    parse_decl(&pbcfd_tif, &name, nullptr, PBCFD, 0);
    pbcfd_tif.set_named_type(nullptr, name.c_str(), 0);
  }

  if (!get_type_ordinal(nullptr, "ProtobufCMessageDescriptor")) {
    parse_decl(&pbcmd_tif, &name, nullptr, PBCMD, 0);
    pbcmd_tif.set_named_type(nullptr, name.c_str(), 0);
  }

}

std::vector<ea_t> search_pbcmd_by_magic()
{
  std::vector<ea_t> matches;
  size_t magic_len = sizeof(PBMAGIC);
  //ea_t start_ea = inf_get_min_ea();
  ea_t start_ea = get_segm_by_name(".data.rel.ro")->start_ea;
  ea_t end_ea = inf_get_max_ea();
  for (ea_t ea = start_ea; ea <= end_ea - magic_len; ea++)
  {
    bool found = true;
    for (size_t i = 0; i < magic_len; i++)
    {
      if (get_byte(ea + i) != static_cast<uint8_t>(PBMAGIC[i]))
      {
        found = false;
        break;
      }
    }
    if (found)
    {
      matches.push_back(ea);
    }
  }
  return matches;
}

struct ProtobufCFieldDescriptor
{
  const char* name;
  uint32_t id;
  int label;
  int type;
  unsigned int quantifier_offset;
  unsigned int offset;
  const void* descriptor;
  const void* default_value;
  uint32_t flags;
  unsigned int reserved_flags;
  void* reserved2;
  void* reserved3;
};

struct ProtobufCMessageDescriptor
{
  uint32_t magic;
  const char* name;
  const char* short_name;
  const char* c_name;
  const char* package_name;
  size_t sizeof_message;
  unsigned int n_fields;
  const ProtobufCFieldDescriptor* fields;
  const unsigned int* fields_sorted_by_name;
  unsigned int n_field_ranges;
  char* field_ranges;
  __int64 message_init;
  void* reserved1;
  void* reserved2;
  void* reserved3;
};

typedef enum {
  PROTOBUF_C_LABEL_REQUIRED,
  PROTOBUF_C_LABEL_OPTIONAL,
  PROTOBUF_C_LABEL_REPEATED,
  PROTOBUF_C_LABEL_NONE,
} ProtobufCLabel;

std::unordered_map<int, std::string> label_map = {
        {PROTOBUF_C_LABEL_REQUIRED,    "required"},
        {PROTOBUF_C_LABEL_OPTIONAL,   "optional"},
        {PROTOBUF_C_LABEL_REPEATED, "repeated"},
        {PROTOBUF_C_LABEL_NONE,    ""}
};

typedef enum {
  PROTOBUF_C_TYPE_INT32,      /**< int32 */
  PROTOBUF_C_TYPE_SINT32,     /**< signed int32 */
  PROTOBUF_C_TYPE_SFIXED32,   /**< signed int32 (4 bytes) */
  PROTOBUF_C_TYPE_INT64,      /**< int64 */
  PROTOBUF_C_TYPE_SINT64,     /**< signed int64 */
  PROTOBUF_C_TYPE_SFIXED64,   /**< signed int64 (8 bytes) */
  PROTOBUF_C_TYPE_UINT32,     /**< unsigned int32 */
  PROTOBUF_C_TYPE_FIXED32,    /**< unsigned int32 (4 bytes) */
  PROTOBUF_C_TYPE_UINT64,     /**< unsigned int64 */
  PROTOBUF_C_TYPE_FIXED64,    /**< unsigned int64 (8 bytes) */
  PROTOBUF_C_TYPE_FLOAT,      /**< float */
  PROTOBUF_C_TYPE_DOUBLE,     /**< double */
  PROTOBUF_C_TYPE_BOOL,       /**< boolean */
  PROTOBUF_C_TYPE_ENUM,       /**< enumerated type */
  PROTOBUF_C_TYPE_STRING,     /**< UTF-8 or ASCII string */
  PROTOBUF_C_TYPE_BYTES,      /**< arbitrary byte sequence */
  PROTOBUF_C_TYPE_MESSAGE,    /**< nested message */
} ProtobufCType;

std::unordered_map<int, std::string> type_map = {
        {PROTOBUF_C_TYPE_INT32,    "int32"},
        {PROTOBUF_C_TYPE_SINT32,   "sint32"},
        {PROTOBUF_C_TYPE_SFIXED32, "sfixed32"},
        {PROTOBUF_C_TYPE_INT64,    "int64"},
        {PROTOBUF_C_TYPE_SINT64,   "sint64"},
        {PROTOBUF_C_TYPE_SFIXED64, "sfixed64"},
        {PROTOBUF_C_TYPE_UINT32,   "uint32"},
        {PROTOBUF_C_TYPE_FIXED32,  "fixed32"},
        {PROTOBUF_C_TYPE_UINT64,   "uint64"},
        {PROTOBUF_C_TYPE_FIXED64,  "fixed64"},
        {PROTOBUF_C_TYPE_FLOAT,    "float"},
        {PROTOBUF_C_TYPE_DOUBLE,   "double"},
        {PROTOBUF_C_TYPE_BOOL,    "bool"},
        {PROTOBUF_C_TYPE_ENUM,     "enum"},
        {PROTOBUF_C_TYPE_STRING,   "string"},
        {PROTOBUF_C_TYPE_BYTES,    "bytes"},
        {PROTOBUF_C_TYPE_MESSAGE,  "message"}
};

qstring read_ascii_string(ea_t address, size_t max_len = 1024) {
  qstring result;
  for (ea_t ea = address; ea < address + max_len; ea++)
  {
    uint8_t byte = get_byte(ea);
    if (byte == 0)
      break;
    result += static_cast<char>(byte);
  }
  return result;
}

std::vector<std::string> handled_results;

void hadnle_matchs(const std::vector<ea_t>& matchs) {
  ProtobufCMessageDescriptor pcmd;
  ProtobufCFieldDescriptor pcfd;
  std::string proto;
  for (auto match : matchs) {
    apply_tinfo(match, pbcmd_tif, TINFO_DEFINITE);
    get_bytes(&pcmd, sizeof(ProtobufCMessageDescriptor),match, GMB_READALL);
    std::string msg_name(read_ascii_string((ea_t)pcmd.short_name).c_str());

    proto.append("\nsyntax = \"proto3\";\n\nmessage\t");
    proto.append(msg_name.c_str());
    proto.append("\t{\n");

    unsigned int msg_nfield = pcmd.n_fields;
    ea_t msg_fields = (ea_t)pcmd.fields;
    for (int i = 0; i < msg_nfield; ++i) {
      int pcfd_size = sizeof(ProtobufCFieldDescriptor);
      ea_t now_field = msg_fields + pcfd_size * i;
      apply_tinfo(now_field, pbcfd_tif, TINFO_DEFINITE);
      get_bytes(&pcfd, pcfd_size, now_field, GMB_READALL);
      std::string field_name(read_ascii_string((ea_t)pcfd.name).c_str());
      std::string field_type = type_map[pcfd.type];
      std::string field_lable = label_map[pcfd.label];
      proto.append("\t");
      if (!field_lable.empty()) {
        proto.append(field_lable.c_str());
        proto.append("\t");
      }
      proto.append(field_type.c_str());
      proto.append("\t");
      proto.append(field_name.c_str());
      proto.append(" = ");
      proto.append(std::to_string(pcfd.id));
      proto.append(";\n");
    }
    proto.append("}");
    handled_results.push_back(proto);
  }
}