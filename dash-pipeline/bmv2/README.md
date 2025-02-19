# DASH Pipeline BM

This directory contains the P4/BMv2-based behavior model implementation of the DASH Pipeline.

At a high level, the DASH pipeline BM serves 2 purposes:

1. It provides a behavior model for DASH pipeline, which can be used for testing in a simulated environment.
2. It provides a generated P4 runtime definition, which can be used to generate the SAI API and SAI adapter code to the behavior model.

## Writing P4/BMv2 code

The workflow of developing the DASH pipeline BM is described in the [DASH workflows doc](../README-dash-workflows.md).

The DASH pipeline BM is written in P4<sub>16</sub> with BMv2 v1model. For specs, please find the referenced docs here:

- P4<sub>16</sub>, P4Runtime, PNA specs: <https://p4.org/specs/>
- V1Model: <https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4>

### P4 annotations for SAI code generation

To better control the SAI API generation, we use P4 annotations to provide any additional information that generator needs.

#### `@SaiVal`: Keys and action parameters

Use `@SaiVal["tag"="value", ...]` format for annotating keys and action parameters.

Available tags are:

- `type`: Specify which SAI object type should be used in generation, e.g. `sai_uint32_t`.
- `default_value`: Override the default value for this key or action parameter.
- `isresourcetype`: When set to "true", we generate a corresponding SAI tag in SAI APIs: `@isresourcetype true`.
- `objects`: Space separated list of SAI object type this value accepts. When set, we force this value to be a SAI object id, and generate a corresponding SAI tag in SAI APIs: `@objects <list>`.
- `order`: Specify the order of the generated attributes in the SAI API header file. This will be particularly useful, when a table has multiple actions, and we add parameters to one of them. The new attributes might be generated in the middle of existing attributes, which breaks ABI compatibility with older version of SAI APIs.
- `isreadonly`: When set to "true", we generate force this value to be read-only in SAI API using: `@flags READ_ONLY`, otherwise, we generate `@flags CREATE_AND_SET`.
- `skipattr`: When set to "true", we skip this attribute in SAI API generation.

#### `@SaiCounter`: Counters

Use `@SaiCounter["tag"="value", ...]` format for annotating counters.

Available tags are:

- `name`: Specify the preferred counter name in SAI API generation, e.g. `outbound_bytes_counter`.
- `action_names`: The counters are usually updated in actions whenever a table is matched. However, v1model doesn't support conditional statements (if-else) in action blocks. Hence, to workaround, sometimes counters should be updated in the actions are updated in the control blocks after the action is called. This tag is used to specify the name of the actions that was supposed to update this counter. e.g. `action1,action2,...`
- `as_attr`: When set to "true", the counters will be generated as an attribute of the SAI object. This is not a normal behavior in SAI, since SAI usually either use get stats APIs or directly use counter IDs. Currently, generating get stats APIs is not supported yet, hence when this is not set, the attribute will be ignored.
- `order`: Specify the order of the generated attributes in the SAI API header file. This will be particularly useful, when a table has multiple actions, and we add parameters to one of them. The new attributes might be generated in the middle of existing attributes, which breaks ABI compatibility with older version of SAI APIs. When `as_attr` is set, it will be compared with the order of other attributes from match keys and action parameters in the same object too.

#### `@SaiTable`: Tables

Use `@SaiTable["tag"="value", ...]` format for annotating tables.

Available tags are:

- `name`: Specify the preferred table name in SAI API generation, e.g. `dash_acl_rule`.
- `api`: Specify which SAI API should be used in generation, e.g. `dash_acl`.
- `api_type`: The type of the API. DASH contains certain tables for handling underlay actions, such as route table. We should not generate header files for these tables but only the lib files without experimental prefix. To enable this behavior, please set the API type to `underlay`.
- `order`: Specify the order of the generated API in the SAI API header file. When multiple tables generates API entries in the same API set, e.g., acl group and acl rules. This explicit attribute helps us keep the order of the generated APIs to keep ABI compatibility.
- `stage`: Specify which stage this table represents for the matching stage type, e.g. `acl.stage1`.
- `isobject`: When set to "true", a top level objects in SAI that attached to switch will be generated. Otherwise, a new type of entry will be generated, if nothing else helps us to determine this table is an object table.
- `ignored`: When set to "true", we skip this table in SAI API generation.
- `match_type`: Some match kinds used in DASH might not be supported by BMv2, such as `list` and `range_list`. In BMv2, we use `optional` to make the P4 compiler happy. However, we still want to generate the correct SAI API. This tag is used to specify the match type in SAI API generation.

For more details, please check the SAI API generation script: [sai_api_gen.py](../SAI/sai_api_gen.py).

## SAI header and implementation generation

The SAI header and implementation files are generated by the [sai_api_gen.py](../SAI/sai_api_gen.py) script. The script takes the P4 runtime json as input and generates the SAI header and implementation files in the [SAI](../SAI) directory.

### SAI type solving

Since the p4 runtime json does not contain the type information, [sai_api_gen.py](../SAI/sai_api_gen.py) has a very basic heuristic picking up the SAI type for the values. The heuristic is intended to stay simple and purely based on the size of the values and match type.

If any more dedicated type is needed, please use the `@SaiVal` annotation to specify the type. Please see the [P4 annotations for SAI code generation](#p4-annotations-for-sai-code-generation) section for more details.
