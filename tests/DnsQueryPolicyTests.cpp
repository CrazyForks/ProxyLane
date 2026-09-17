#include <assert.h>
#include "DnsQueryPolicy.h"

int main()
{
	using namespace DnsQueryPolicy;

	addrinfo hints = {};
	assert(!IsPassiveLookup<addrinfo>(NULL));
	assert(!IsPassiveLookup(&hints));

	hints.ai_flags = AI_PASSIVE;
	assert(IsPassiveLookup(&hints));

	hints.ai_flags = AI_PASSIVE | AI_CANONNAME;
	assert(IsPassiveLookup(&hints));

	hints.ai_flags = AI_CANONNAME;
	assert(!IsPassiveLookup(&hints));
	return 0;
}
