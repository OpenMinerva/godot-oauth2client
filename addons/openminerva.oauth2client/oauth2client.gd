# --- License
# File: /oauth2client.gd
# Project: openminerva.oauth2client
# Created Date: 04 May 2026
# Copyright (c) 2026 OpenMinerva
# License: MIT License
# Authors: Armored Dragon
# --- License

extends RefCounted

# TODO: State CSRF protection
# TODO: Handle shutdown / dispose?

var tree = Engine.get_main_loop() as SceneTree
const LOCALHOST: String = "127.0.0.1"
var host: String = ""
var host_port: int = 0
var client_id: String = ""
var port: int = 0
var logger: Variant = null
var redirect_server = TCPServer.new()
var debug_mode: bool = false
var pkce: String = _random_string()
var http_lib: Variant = null

var success_html: String = ""
var result_page_css: String = ""
var result_page_favicon: String = ""

func _init(p_host: String, p_host_port: int, p_client_id: String, p_port: int = 54000, p_logger: Variant = null, p_http_lib: Variant = null, p_is_debug: bool = false) -> void:
	host = p_host
	host_port = p_host_port
	client_id = p_client_id
	port = p_port
	logger = p_logger
	debug_mode = p_is_debug

	if p_http_lib && p_http_lib.has_method("req"):
		lib_log("Using supplied HTTP Library.")
		http_lib = p_http_lib
	else:
		lib_log("Using fallback HTTP Library.")
		http_lib = preload("res://addons/openminerva.oauth2client/http.gd").new()

	# Read the success HTML page.
	var html = FileAccess.open("res://addons/openminerva.oauth2/page/index.html", FileAccess.READ)
	if html:
		var content = html.get_as_text()
		html.close()
		success_html = content

	# CSS Page
	var css = FileAccess.open("res://addons/openminerva.oauth2/page/index.css", FileAccess.READ)
	if css:
		var content = css.get_as_text()
		css.close()
		result_page_css = content

	# Read Favicon
	var fav_file = FileAccess.open("res://addons/openminerva.oauth2/page/logo.webp", FileAccess.READ)
	if fav_file:
		var buffer = fav_file.get_buffer(fav_file.get_length())
		fav_file.close()

		var base64_str = Marshalls.raw_to_base64(buffer)

		result_page_favicon = "<link rel=\"icon\" href=\"data:image/webp;base64," + base64_str + "\">"

	lib_log("OAuth2 library initialized.")

func authenticate() -> Dictionary:
	lib_log("Starting authentication flow for '%s'." % host)

	var uri_parts := [
		"client_id=%s" % client_id,
		"redirect_uri=http://%s:%s" % [LOCALHOST, port],
		"response_type=code", # TODO: response_type
		"scope=openid offline_access", # TODO: scope
		"response_mode=query",
		"code_challenge_method=S256",
		"code_challenge=%s" % _get_code_challenge(pkce),
		"prompt=consent"
	]
	# TODO: Deconstruct so that it is easier to read.
	var uri = ":".join([host, host_port]) + "/oauth/authorize" + "?" + "&".join(uri_parts)
	OS.shell_open(uri)

	redirect_server.listen(port, LOCALHOST)
	lib_log("Started redirect server.")

	var _auth_code = await _wait_for_auth_code()

	redirect_server = TCPServer.new()
	lib_log("Closed redirect server.")

	var oauth_data: Dictionary = await _exchange_code(_auth_code)
	return oauth_data

func validate(oauth_data: Dictionary) -> bool:
	if oauth_data.access_token == "":
		lib_log("No access token provided to validate. Returning false.")
		return false

	var form_parts := [
		"client_id=%s" % client_id,
		"token=%s" % oauth_data.access_token,
	]
	var form_string: String = "&".join(form_parts)
	var introspect_response = await http_lib.req(HTTPClient.Method.METHOD_POST, host, "/oauth/token/introspection", host_port, ["Accept: application/json", "Content-Type: application/x-www-form-urlencoded"], form_string)
	
	# TODO: Safe JSON checking / parsing
	if introspect_response.ok == false:
		lib_log("Unknown error parsing the introspection response.")
		return false

	# FIXME: No validation of JSON before parsing, causes errors!
	introspect_response = JSON.parse_string(introspect_response.body)
	var is_active: bool = introspect_response.active
	return is_active

func lib_log(p_msg: String) -> void:
	if logger.has_method("log"):
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
	lib_log("Formatting HTTP response.")
	var request = connection.get_string(connection.get_available_bytes())

	# Extract code from URL
	# FIXME: Not safe auth_code extraction.
	var temp_auth_code: String = request.split("code=")[1].split("&iss=")[0].strip_edges()

	lib_log("Got authentication code: '%s'." % (temp_auth_code if debug_mode else "[HIDDEN]"))

	# Add the favicon to the page.
	success_html = success_html.replace('<link rel="icon" type="image/svg" href="logo.svg" />', result_page_favicon)

	# Add the stylesheet to the page.
	success_html = success_html.replace('<link rel="stylesheet" type="text/css" href="index.css">', "<style>%s</style>" % result_page_css)

	# Send success.
	var html_response = "HTTP/1.1 200 OK\r\n"
	html_response += "Content-Type: text/html\r\n"
	html_response += "Connection: close\r\n\r\n"
	html_response += success_html
	connection.put_data(html_response.to_utf8_buffer())

	# Disconnect
	connection.disconnect_from_host()

	return temp_auth_code

func _exchange_code(code: String) -> Dictionary:
	lib_log("Exchanging auth code for tokens.")

	var form_parts := [
		"client_id=%s" % client_id,
		"grant_type=authorization_code",
		"code=%s" % code,
		"redirect_uri=http://%s:%s" % [LOCALHOST, port],
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
	lib_log("Formatting response tokens.")
	# TODO: Error checks to prevent overwriting with bad data.
	var oauth_data = {
		"access_token" = response.get("access_token"),
		"refresh_token" = response.get("refresh_token"),
		"id_token" = response.get("id_token"),
		"access_token_expiry" = response.get("expires_in")
	}

	return oauth_data
