#pragma once

#include <string.h>

namespace DnsNamePolicy
{
	inline bool EqualsDnsName(const char *left, const char *right)
	{
		return left && left[0] && right && right[0] &&
			_stricmp(left, right) == 0;
	}

	inline bool IsLocalhost(const char *name)
	{
		return EqualsDnsName(name, "localhost");
	}
}
