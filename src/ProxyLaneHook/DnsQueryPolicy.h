#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

namespace DnsQueryPolicy
{
	template <typename TAddressInfo>
	inline bool IsPassiveLookup(const TAddressInfo *hints)
	{
		return hints && (hints->ai_flags & AI_PASSIVE) != 0;
	}
}
