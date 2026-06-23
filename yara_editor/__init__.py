"""YARA-aware Ace editor component for Streamlit."""
import os
import streamlit as st
import streamlit.components.v1 as components

build_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
_component_func = components.declare_component("yara_editor", path=build_dir)


def yara_editor(code="", height=30, response_mode="blur", key=None):
    component_value = _component_func(
        code=code,
        height=height,
        response_mode=response_mode,
        key=key,
        default={"text": "", "type": "ready"},
    )
    return component_value
