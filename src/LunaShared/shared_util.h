#pragma once

// General helpers
#define NOT_WHITESPACE(expr) (expr != ' ' && expr != '\t' && expr != '\n' && expr != '\r')
#define IS_WHITESPACE(expr) (expr == ' ' || expr == '\t' || expr == '\n' || expr == '\r')