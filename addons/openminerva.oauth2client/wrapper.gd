# --- License
# File: /addons/openminerva.oauth2/wrapper.gd
# Project: openminerva.oauth2
# Created Date: 05 May 2026
# Copyright (c) 2026 OpenMinerva
# License: MIT License
# Authors: Armored Dragon
# --- License

extends Node

const OAuth2ClientInternal = preload("res://addons/openminerva.oauth2client/oauth2client.gd")

func new(p_host: String, p_host_port: int, p_client_id: String, p_port: int = 54000, p_logger: Variant = null, p_http_lib: Variant = null, p_is_debug: bool = false) -> RefCounted:
	return OAuth2ClientInternal.new(p_host, p_host_port, p_client_id, p_port, p_logger, p_http_lib, p_is_debug)