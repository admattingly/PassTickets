/* REXX */
/*
 * Generate a HMAC key and store it in the CKDS
 */
label = ""
arg kbl label .
if label = "" then do
  say " "
  say "Usage: genhmac key_bit_length key_label"
  say " "
  say "  key_bit_length    must be between 80 and 2048 (or between 256 and"
  say "                    2048 for RACF Enhanced Passtickets - 512 bits"
  say "                    is recommended)"
  say " "
  say "  key_label         CKDS key label"
  say " "
  return 8
end

/* make sure key bit length is valid */
if kbl < 80 | kbl > 2048 then do
  say "ERROR: key bit length, "kbl", is not in valid range of 80 to 2048"
  return 12
end
if kbl < 256 then do
  say "WARNING: key bit length, "kbl", is too short for RACF Enhanced" ,
      "Passtickets - minimum is 256"
end

/* Call CSNBKTB2 to build skeleton token */
return_code                 = D2C(0, 4)
reason_code                 = D2C(0, 4)
exit_data_length            = D2C(0, 4)
exit_data                   = ""
rule_array_count            = D2C(5, 4)
rule_array                  = "INTERNALHMAC    NO-KEY  MAC     GENERATE"
clear_key_bit_length        = D2C(0, 4)
clear_key_value             = ""
key_name_length             = D2C(0, 4)
key_name                    = ""
user_associated_data_length = D2C(0, 4)
user_associated_data        = ""
token_data_length           = D2C(0, 4)
token_data                  = ""
service_data_length         = D2C(0, 4)
service_data                = ""
target_key_token_length     = D2C(725, 4)
target_key_token            = COPIES('00'x, 725)

address LINKPGM "CSNBKTB2"                             ,
  "return_code"                 "reason_code"          ,
  "exit_data_length"            "exit_data"            ,
  "rule_array_count"            "rule_array"           ,
  "clear_key_bit_length"        "clear_key_value"      ,
  "key_name_length"             "key_name"             ,
  "user_associated_data_length" "user_associated_data" ,
  "token_data_length"           "token_data"           ,
  "service_data_length"         "service_data"         ,
  "target_key_token_length"     "target_key_token"
  
say "CSNBKTB2          rc="C2D(return_code)", reason="C2D(reason_code)
if C2D(return_code) >= 8 then do
  say "ERROR: Failed to build skeleton key token"
  return 12
end
/* say "Skeleton token:  " ,
  C2X(LEFT(target_key_token, C2D(target_key_token_length))) */

/* Call CSNBRNGL to generate a random key value */
bytelen = TRUNC((kbl + 7) / 8)
return_code                 = D2C(0, 4)
reason_code                 = D2C(0, 4)
exit_data_length            = D2C(0, 4)
exit_data                   = ""
rule_array_count            = D2C(1, 4)
rule_array                  = "RANDOM  "
key_identifier_length       = D2C(0, 4)
key_identifier              = ""
random_number_length        = D2C(bytelen, 4)
random_number               = COPIES('00'x, bytelen)

address LINKPGM "CSNBRNGL"                             ,
  "return_code"                 "reason_code"          ,
  "exit_data_length"            "exit_data"            ,
  "rule_array_count"            "rule_array"           ,
  "key_identifier_length"       "key_identifier"       ,
  "random_number_length"        "random_number"
  
say "CSNBRNGL          rc="C2D(return_code)", reason="C2D(reason_code)
if C2D(return_code) >= 8 then do
  say "ERROR: Failed generate random clear key value"
  return 12
end
say "Clear key value: " C2X(random_number)

/* Call CSNBKPI2 to import the clear key value */
return_code                 = D2C(0, 4)
reason_code                 = D2C(0, 4)
exit_data_length            = D2C(0, 4)
exit_data                   = ""
rule_array_count            = D2C(3, 4)
rule_array                  = "HMAC    FIRST   MIN1PART"
key_part_bit_length         = D2C(kbl, 4)
key_part                    = random_number    /* from CSNBRNGL */
key_identifier_length       = D2C(725, 4)
key_identifier              = target_key_token /* from CSNBKTB2 */

address LINKPGM "CSNBKPI2"                             ,
  "return_code"                 "reason_code"          ,
  "exit_data_length"            "exit_data"            ,
  "rule_array_count"            "rule_array"           ,
  "key_part_bit_length"         "key_part"             ,
  "key_identifier_length"       "key_identifier"       

say "CSNBKPI2 FIRST    rc="C2D(return_code)", reason="C2D(reason_code)
if C2D(return_code) >= 8 then do
  say "ERROR: Failed to import clear key value into key token"
  return 12
end

/* Call CSNBKPI2 again to COMPLETE the key token */
return_code                 = D2C(0, 4)
reason_code                 = D2C(0, 4)
exit_data_length            = D2C(0, 4)
exit_data                   = ""
rule_array_count            = D2C(2, 4)
rule_array                  = "HMAC    COMPLETE"
key_part_bit_length         = D2C(0, 4)
key_part                    = ""
key_identifier_length       = D2C(725, 4)
key_identifier              = key_identifier /* from CSNBKPI2 FIRST */

address LINKPGM "CSNBKPI2"                             ,
  "return_code"                 "reason_code"          ,
  "exit_data_length"            "exit_data"            ,
  "rule_array_count"            "rule_array"           ,
  "key_part_bit_length"         "key_part"             ,
  "key_identifier_length"       "key_identifier"       

say "CSNBKPI2 COMPLETE rc="C2D(return_code)", reason="C2D(reason_code)
if C2D(return_code) >= 8 then do
  say "ERROR: Failed to import clear key value into key token"
  return 12
end

/* Call CSNBKRC2 to create a record in the CKDS */
return_code                 = D2C(0, 4)
reason_code                 = D2C(0, 4)
exit_data_length            = D2C(0, 4)
exit_data                   = ""
rule_array_count            = D2C(0, 4)
rule_array                  = ""
key_label                   = OVERLAY(label, COPIES(' ', 64))
key_token_length            = key_identifier_length /* from CSNBKPI2 */
key_token                   = key_identifier        /* from CSNBKPI2 */

address LINKPGM "CSNBKRC2"                             ,
  "return_code"                 "reason_code"          ,
  "exit_data_length"            "exit_data"            ,
  "rule_array_count"            "rule_array"           ,
  "key_label"                                          ,
  "key_token_length"            "key_token"       

say "CSNBKRC2          rc="C2D(return_code)", reason="C2D(reason_code)
if C2D(return_code) >= 8 then do
  say "ERROR: Failed to create CKDS record"
  return 12
end

say "HMAC key successfully written to CKDS"
