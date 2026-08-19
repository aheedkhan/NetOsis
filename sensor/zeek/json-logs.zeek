@load base/frameworks/logging
@load policy/tuning/json-logs

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
