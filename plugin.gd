# --- License
# File: /addons/openminerva.oauth2/plugin.gd
# Project: openminerva.oauth2
# Created Date: 05 May 2026
# Copyright (c) 2026 OpenMinerva
# License: MIT License
# Authors: Armored Dragon
# --- License

@tool
extends EditorPlugin

const AUTOLOAD_NAME = "OAuth2Client"
const SCRIPT_PATH = "res://addons/openminerva.oauth2client/wrapper.gd"

func _enter_tree():
	add_autoload_singleton(AUTOLOAD_NAME, SCRIPT_PATH)

func _exit_tree():
	remove_autoload_singleton(AUTOLOAD_NAME)
