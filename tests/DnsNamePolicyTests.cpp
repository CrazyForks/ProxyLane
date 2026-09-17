#include <assert.h>
#include "DnsNamePolicy.h"

int main()
{
	using namespace DnsNamePolicy;

	assert(IsLocalhost("localhost"));
	assert(IsLocalhost("LOCALHOST"));
	assert(IsLocalhost("LocalHost"));

	assert(!IsLocalhost(NULL));
	assert(!IsLocalhost(""));
	assert(!IsLocalhost("localhost."));
	assert(!IsLocalhost("sub.localhost"));
	assert(!IsLocalhost("localhost.example"));
	assert(!IsLocalhost("127.0.0.1"));

	assert(EqualsDnsName("DESKTOP-ABC123", "desktop-abc123"));
	assert(EqualsDnsName("Desktop-Abc123", "DESKTOP-ABC123"));
	assert(!EqualsDnsName("DESKTOP-ABC123.", "DESKTOP-ABC123"));
	assert(!EqualsDnsName("DESKTOP-ABC123.example", "DESKTOP-ABC123"));
	assert(!EqualsDnsName("DESKTOP-ABC123-extra", "DESKTOP-ABC123"));
	assert(!EqualsDnsName(NULL, "DESKTOP-ABC123"));
	assert(!EqualsDnsName("DESKTOP-ABC123", NULL));
	assert(!EqualsDnsName("", "DESKTOP-ABC123"));
	assert(!EqualsDnsName("DESKTOP-ABC123", ""));
	return 0;
}
