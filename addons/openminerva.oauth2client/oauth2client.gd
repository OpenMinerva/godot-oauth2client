# --- License
# File: /oauth2client.gd
# Project: openminerva.oauth2client
# Created Date: 04 May 2026
# Copyright (c) 2026 OpenMinerva
# License: MIT License
# Authors: Armored Dragon
# --- License

extends RefCounted

const LOCALHOST: String = "127.0.0.1"
var host: String = "" # The server to authenticate with.
var host_port: int = 0 # The port of the server to authenticate with.
var client_id: String = "" # The client ID to use that was configured with the server to authenticate with.
var callback_port: int = 0 # Our port we use to host our callback server.
var logger: Variant = null # Optional logging library. (Must have ".log()" method!)
var http_lib: Variant = null # Optional HTTP library. This is not recommended to be changed unless you know what you are doing.
var redirect_server: TCPServer = TCPServer.new()
var debug_mode: bool = false # Is this a debugging instance? Logging hides sensitive data by default, when enabled, we display that sensitive data.
var pkce: String = _random_string() # PKCE is used to generate code_challenges.
var csrf_state: String = _random_string()
var tree = Engine.get_main_loop() as SceneTree

# Local files used in serving the callback page.
var index_html: String = ""
var css_html: String = ""
var favicon_html: String = ""

# Enums
enum OAUTH2_CLIENT_RESULT {
	OK = 0,
	UNKNOWN_ERROR = 1,
	HTTP_REQUEST_FAILED = 2,
	MISSING_REQUIRED_PARAM = 3,
	JSON_PARSE_FAILED = 4
}

func _init(p_host: String, p_host_port: int, p_client_id: String, p_callback_port: int = 54000, p_logger: Variant = null, p_http_lib: Variant = null, p_debug_mode: bool = false) -> void:
	host = p_host
	host_port = p_host_port
	client_id = p_client_id
	callback_port = p_callback_port
	debug_mode = p_debug_mode

	_setup_logger(p_logger)
	_setup_http(p_http_lib)
	_read_local_files()

	_lib_log("OAuth2 library initialized.")
	return

func authenticate() -> Dictionary:
	var uri_with_port: String = ":".join([host, host_port])
	var complete_uri: String = ""
	var code_challenge: String = _get_code_challenge(pkce)
	var uri_query: String = "&".join([
		"client_id=%s" % client_id,
		"redirect_uri=http://%s:%s" % [LOCALHOST, callback_port],
		"response_type=code",
		"scope=openid offline_access",
		"response_mode=query",
		"code_challenge_method=S256",
		"code_challenge=%s" % code_challenge,
		"prompt=consent",
		"state=%s" % csrf_state
	])
	_lib_log("Starting authentication flow for '%s'." % host)
	
	complete_uri = uri_with_port + "/oauth/authorize?" + uri_query

	OS.shell_open(complete_uri)

	redirect_server.listen(callback_port, LOCALHOST)
	_lib_log("Started redirect server.")

	var _auth_code = await _wait_for_auth_code()

	redirect_server = TCPServer.new()
	_lib_log("Closed redirect server.")

	var oauth_data: Dictionary = await _exchange_code(_auth_code)
	return _return_status(OAUTH2_CLIENT_RESULT.OK, oauth_data)

func validate(oauth_data: Dictionary) -> Dictionary:
	var _introspect_response: Dictionary = {}
	var _introspect_body: String = ""
	var _introspect_parsed_body: Dictionary = {}
	var _oauth_token_active: bool = false
	var form: String = "&".join([
		"client_id=%s" % client_id,
		"token=%s" % oauth_data.access_token,
	])

	if oauth_data.access_token == "":
		_lib_log("No access token provided to validate. Returning false.")
		return _return_status(OAUTH2_CLIENT_RESULT.OK, false)

	_introspect_response = await http_lib.req(HTTPClient.Method.METHOD_POST, host, "/oauth/token/introspection", host_port, ["Accept: application/json", "Content-Type: application/x-www-form-urlencoded"], form)
	if _introspect_response.ok == false:
		_lib_log("Unknown error parsing the introspection response.")
		return _return_status(OAUTH2_CLIENT_RESULT.HTTP_REQUEST_FAILED)

	_introspect_body = _introspect_response.get("body")
	_introspect_parsed_body = JSON.parse_string(_introspect_body)

	if _introspect_parsed_body == null:
		return _return_status(OAUTH2_CLIENT_RESULT.JSON_PARSE_FAILED)

	_oauth_token_active = _introspect_parsed_body.active
	return _return_status(OAUTH2_CLIENT_RESULT.OK, _oauth_token_active)

func _lib_log(p_msg: String) -> void:
	if logger:
		logger.log("[OAuth2] %s" % p_msg)
	else:
		print("[OAuth2] %s" % p_msg)

func _random_string():
	const TARGET_LENGTH = 50
	const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var return_value = ""
	var rng = RandomNumberGenerator.new()
	rng.randomize()

	for i in TARGET_LENGTH:
		return_value += ALPHABET[rng.randi_range(0, ALPHABET.length() - 1)]

	return return_value

func _get_code_challenge(verifier: String) -> String:
	var ctx = HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	ctx.update(verifier.to_utf8_buffer())
	var hash_bytes = ctx.finish()
	var base64_str = Marshalls.raw_to_base64(hash_bytes)

	base64_str = _base64_to_base64url(base64_str)

	return base64_str

func _base64_to_base64url(input_value: String):
	var base64_str = input_value.replace("+", "-")
	base64_str = base64_str.replace("/", "_")

	while base64_str.ends_with("="):
		base64_str = base64_str.substr(0, base64_str.length() - 1)

	return base64_str

func _wait_for_auth_code() -> String:
	var code: String = ""

	# FIXME: Indefinite loop risk! 
	while code == "":
		if redirect_server.is_connection_available():
			code = _handle_auth_callback(redirect_server.take_connection())
		else:
			await tree.process_frame

	return code

func _handle_auth_callback(connection: StreamPeerTCP) -> String:
	_lib_log("Formatting HTTP response.")
	var _query_params: Dictionary
	var _auth_code: String

	var request = connection.get_string(connection.get_available_bytes())
	_query_params = _get_query_params(request)

	# Validate the csrf state
	if csrf_state != _query_params.get("state"):
		_lib_log("'State' was different than expected. Someone is probably doing something naughty!")
		return ""

	# Get the auth code
	_auth_code = _query_params.get("code")

	_lib_log("Got authentication code: '%s'." % (_auth_code if debug_mode else "[HIDDEN]"))

	# Add the favicon to the page.
	index_html = index_html.replace('<link rel="icon" type="image/svg" href="logo.svg" />', favicon_html)

	# Add the stylesheet to the page.
	index_html = index_html.replace('<link rel="stylesheet" type="text/css" href="index.css">', css_html)

	# Send success.
	var html_response = "HTTP/1.1 200 OK\r\n"
	html_response += "Content-Type: text/html\r\n"
	html_response += "Connection: close\r\n\r\n"
	html_response += index_html
	connection.put_data(html_response.to_utf8_buffer())

	# Disconnect
	connection.disconnect_from_host()

	return _auth_code

func _exchange_code(code: String) -> Dictionary:
	_lib_log("Exchanging auth code for tokens.")

	var form_parts := [
		"client_id=%s" % client_id,
		"grant_type=authorization_code",
		"code=%s" % code,
		"redirect_uri=http://%s:%s" % [LOCALHOST, callback_port],
		"code_challenge_method=S256",
		"code_verifier=%s" % pkce,
	]

	# FIXME: No validation of JSON before parsing, causes errors!
	var form_string: String = "&".join(form_parts)
	var exchange_response = await http_lib.req(HTTPClient.Method.METHOD_POST, host, "/oauth/token", host_port, ["Accept: application/json", "Content-Type: application/x-www-form-urlencoded"], form_string)
	var token_data = JSON.parse_string(exchange_response.get("body"))
	var formatted: Dictionary = _get_tokens_from_response(token_data)
	return formatted

func _get_tokens_from_response(response: Dictionary) -> Dictionary:
	_lib_log("Formatting response tokens.")

	var oauth_data = {
		"access_token" = response.get("access_token"),
		"refresh_token" = response.get("refresh_token"),
		"id_token" = response.get("id_token"),
		"access_token_expiry" = response.get("expires_in")
	}

	return oauth_data

func _setup_logger(p_logger) -> void:
	if p_logger && p_logger.has_method("log"):
		logger = p_logger
		_lib_log("Using supplied Logger Library.")
	else:
		_lib_log("Logger not supplied, using fallback.")
	return
	
func _setup_http(p_http_lib) -> void:
	if p_http_lib && p_http_lib.has_method("req"):
		_lib_log("Using supplied HTTP Library.")
		http_lib = p_http_lib
	else:
		_lib_log("Using fallback HTTP Library.")
		http_lib = preload("res://addons/openminerva.oauth2client/http.gd").new()
	return

func _read_local_files() -> void:
	_lib_log("Reading local files.")

	# Read HTML page.
	var html = FileAccess.open("res://addons/openminerva.oauth2client/page/index.html", FileAccess.READ)
	if html:
		var content = html.get_as_text()
		html.close()
		index_html = content
	else:
		_lib_log("Failed to read the callback page. Ensure the 'index.html' page is located in the '/openmineerva/oauth2client/page' directory.")

	# Read CSS
	var css = FileAccess.open("res://addons/openminerva.oauth2client/page/index.css", FileAccess.READ)
	if css:
		var content = css.get_as_text()
		css.close()
		css_html = "<style>%s</style>" % content
	else:
		_lib_log("Failed to read the callback page stylesheet. Ensure that 'index.css' stylesheet is located in the '/openmineerva/oauth2client/page' directory.")

	# Read Favicon.
	var fav_file = FileAccess.open("res://addons/openminerva.oauth2client/page/logo.webp", FileAccess.READ)
	if fav_file:
		var buffer = fav_file.get_buffer(fav_file.get_length())
		fav_file.close()

		var base64_str = Marshalls.raw_to_base64(buffer)

		favicon_html = "<link rel=\"icon\" href=\"data:image/webp;base64," + base64_str + "\">"
	else:
		_lib_log("Failed to read the callback page favicon. Ensure that 'logo.webp' favicon is located in the '/openmineerva/oauth2client/page' directory.")
	return

func _get_query_params(request: String) -> Dictionary:
	var _url: String = request.split(" ")[1]
	var _return_object: Dictionary = {}
	var _regex = RegEx.new()
	var _regex_search: Array[RegExMatch]

	_regex.compile("([^?&=]+)=([^&]*)")
	_regex_search = _regex.search_all(_url)

	for _result in _regex_search:
		var _key = _result.get_string(1)
		var _value = _result.get_string(2)
		_return_object.set(_key.uri_decode(), _value.uri_decode())

	return _return_object

func _return_status(state: OAUTH2_CLIENT_RESULT, data: Variant = null) -> Dictionary:
	return {"ok": state, "data": data}