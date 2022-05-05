#include "DNS_Server.h"
#include <lwip/def.h>
#include <Arduino.h>
#include <memory>

// #include <driver/uart.h>

#define DNS_HEADER_SIZE sizeof(DNSHeader)

//-------------------------------------------------------------------------------

//-------------------------------------------------------------------------------
char dnsBuffer[ 256 ];

//-------------------------------------------------------------------------------
DNS_Server::DNS_Server()
{
	_ttl = lwip_htonl(60);
	_errorReplyCode = DNSReplyCode::NonExistentDomain;
	clearRecords();
}

//-------------------------------------------------------------------------------
bool DNS_Server::start(const uint16_t port)
{
	_port = port;
	return _udp.begin(_port) == 1;
}

//-------------------------------------------------------------------------------
void DNS_Server::setErrorReplyCode(const DNSReplyCode &replyCode)
{
	_errorReplyCode = replyCode;
}

//-------------------------------------------------------------------------------
void DNS_Server::setTTL(const uint32_t &ttl)
{
	_ttl = lwip_htonl(ttl);
}

//-------------------------------------------------------------------------------
void DNS_Server::stop()
{
	_udp.stop();
}

//-------------------------------------------------------------------------------
void DNS_Server::addRecord(const char* domainName, const IPAddress &resolvedIP)
{
	
	// downcaseAndRemoveWwwPrefix( domainName );

	for( uint16_t i = 0; i < MAX_DNS_RECORDS; i++ ){
		if( _domainNames[ i ] [ 0 ] == '\0' && _domainNames[ i ] [ 1 ] == '\0' && _domainNames[ i ] [ 2 ] == '\0' ){
			strcpy( _domainNames[ i ], domainName );
			_resolvedIPs[ i ][ 0 ] = resolvedIP[ 0 ];
			_resolvedIPs[ i ][ 1 ] = resolvedIP[ 1 ];
			_resolvedIPs[ i ][ 2 ] = resolvedIP[ 2 ];
			_resolvedIPs[ i ][ 3 ] = resolvedIP[ 3 ];
			break;
		}
	}
}

//-------------------------------------------------------------------------------
int16_t DNS_Server::findRecord(const char* domainName, uint8_t length)
{
	uint16_t i = 0;
	uint16_t j = 0;
	int16_t res = -1;

	const char* start = domainName;

	if( strncasecmp( "www.", start, 4 ) == 0 ){
		start += 4;
		length -= 4;
	}

	for( i = 0; i <= length; i++ ){
		if( start[ i ] == '\0' ){
			j = 1;
			break;
		}
	}

	if( !j ) return -2;

	for( i = 0; i < MAX_DNS_RECORDS; i++ ){
		size_t len = strlen( _domainNames[ i ] );
		if( strncasecmp( start, _domainNames[ i ], len ) == 0 || ( len == 1 && _domainNames[ i ][ 0 ] == '*' ) ){
			res = i;
			break;
		}
	}

	return res;
}

//-------------------------------------------------------------------------------
void DNS_Server::downcaseAndRemoveWwwPrefix(String &domainName)
{
	domainName.toLowerCase();
	if (domainName.startsWith("www."))
			domainName.remove(0, 4);
}

//-------------------------------------------------------------------------------
void DNS_Server::respondToRequest(uint8_t *buffer, size_t length)
{
	DNSHeader *dnsHeader;
	uint8_t *query, *start;
	size_t remaining, labelLength, queryLength;
	uint16_t qtype, qclass;

	dnsHeader = (DNSHeader *)buffer;

	// Must be a query for us to do anything with it
	if (dnsHeader->QR != DNS_QR_QUERY)
		return;

	// If operation is anything other than query, we don't do it
	if (dnsHeader->OPCode != DNS_OPCODE_QUERY)
		return replyWithError(dnsHeader, DNSReplyCode::NotImplemented);

	// Only support requests containing single queries - everything else
	// is badly defined
	if (dnsHeader->QDCount != lwip_htons(1))
		return replyWithError(dnsHeader, DNSReplyCode::FormError);

	// We must return a FormError in the case of a non-zero ARCount to
	// be minimally compatible with EDNS resolvers
	if (dnsHeader->ANCount != 0 || dnsHeader->NSCount != 0
			|| dnsHeader->ARCount != 0)
		return replyWithError(dnsHeader, DNSReplyCode::FormError);

	// Even if we're not going to use the query, we need to parse it
	// so we can check the address type that's being queried

	query = start = buffer + DNS_HEADER_SIZE;
	remaining = length - DNS_HEADER_SIZE;
	while (remaining != 0 && *start != 0) {
		labelLength = *start;
		if (labelLength + 1 > remaining)
	return replyWithError(dnsHeader, DNSReplyCode::FormError);
		remaining -= (labelLength + 1);
		start += (labelLength + 1);
	}

	// 1 octet labelLength, 2 octet qtype, 2 octet qclass
	if (remaining < 5)
		return replyWithError(dnsHeader, DNSReplyCode::FormError);

	start += 1; // Skip the 0 length label that we found above

	memcpy(&qtype, start, sizeof(qtype));
	start += 2;
	memcpy(&qclass, start, sizeof(qclass));
	start += 2;

	queryLength = start - query;

	if (qclass != lwip_htons(DNS_QCLASS_ANY)
			&& qclass != lwip_htons(DNS_QCLASS_IN))
		return replyWithError(dnsHeader, DNSReplyCode::NonExistentDomain,
				query, queryLength);

	if (qtype != lwip_htons(DNS_QTYPE_A)
			&& qtype != lwip_htons(DNS_QTYPE_ANY))
		return replyWithError(dnsHeader, DNSReplyCode::NonExistentDomain,
				query, queryLength);

	//build dnsString
	if( query[ 0 ] < 0x20 ){
		uint8_t totalLen = queryLength;
		uint8_t offset = 1;
		uint8_t len = query[ 0 ];
		uint8_t wi = 0;

		while( totalLen >= len ){
			if( wi > 0 ) dnsBuffer[ wi++ ] = '.';
			for( uint8_t i = 0; i < len; i++ ){
				dnsBuffer[ wi++ ] = (char)query[ offset + i ];
			}
			totalLen -= len;
			offset += len;
			len = query[ offset ];
			offset++;
			if( len == 0 ) break;
		}
		dnsBuffer[ wi++ ] = '\0';
	}

	int16_t result = findRecord( dnsBuffer, strlen( dnsBuffer ) );

	// uart_write_bytes( UART_NUM_0, "DNS Request: ", 13 );
	// // printHexData2( query, queryLength );
	// uart_write_bytes( UART_NUM_0, dnsBuffer, strlen( dnsBuffer ) );
	// uart_write_bytes( UART_NUM_0, " Find: ", 7 );
	// char tVal[ 16 ];
	// itoa( result, tVal, 10 ); uart_write_bytes( UART_NUM_0, tVal, strlen( tVal ) );
	// uart_write_bytes( UART_NUM_0, "\n", 1 );

	if( result >= 0 ){
		return replyWithIP( dnsHeader, query, queryLength, _resolvedIPs[ result ] );
	}

	return replyWithError( dnsHeader, _errorReplyCode, query, queryLength );
}

//-------------------------------------------------------------------------------
void DNS_Server::processNextRequest()
{
	size_t currentPacketSize;

	currentPacketSize = _udp.parsePacket();
	if (currentPacketSize == 0)
		return;

	// The DNS RFC requires that DNS packets be less than 512 bytes in size,
	// so just discard them if they are larger
	if (currentPacketSize > MAX_DNS_PACKETSIZE)
		return;

	// If the packet size is smaller than the DNS header, then someone is
	// messing with us
	if (currentPacketSize < DNS_HEADER_SIZE)
		return;

	std::unique_ptr<uint8_t[]> buffer(new (std::nothrow) uint8_t[currentPacketSize]);
	if (buffer == nullptr)
		return;

	_udp.read(buffer.get(), currentPacketSize);
	respondToRequest(buffer.get(), currentPacketSize);
}

//-------------------------------------------------------------------------------
void DNS_Server::writeNBOShort(uint16_t value)
{
	 _udp.write((unsigned char *)&value, 2);
}

//-------------------------------------------------------------------------------
void DNS_Server::replyWithIP(DNSHeader *dnsHeader, unsigned char * query, size_t queryLength, unsigned char* ip)
{
	uint16_t value;

	dnsHeader->QR = DNS_QR_RESPONSE;
	dnsHeader->QDCount = lwip_htons(1);
	dnsHeader->ANCount = lwip_htons(1);
	dnsHeader->NSCount = 0;
	dnsHeader->ARCount = 0;

	_udp.beginPacket(_udp.remoteIP(), _udp.remotePort());
	_udp.write((unsigned char *) dnsHeader, sizeof(DNSHeader));
	_udp.write(query, queryLength);

	// Rather than restate the name here, we use a pointer to the name contained
	// in the query section. Pointers have the top two bits set.
	value = 0xC000 | DNS_HEADER_SIZE;
	writeNBOShort(lwip_htons(value));

	// Answer is type A (an IPv4 address)
	writeNBOShort(lwip_htons(DNS_QTYPE_A));

	// Answer is in the Internet Class
	writeNBOShort(lwip_htons(DNS_QCLASS_IN));

	// Output TTL (already NBO)
	_udp.write((unsigned char*)&_ttl, 4);

	// Length of RData is 4 bytes (because, in this case, RData is IPv4)
	writeNBOShort(lwip_htons(sizeof(ip)));
	_udp.write(ip, sizeof(ip));
	_udp.endPacket();
}

//-------------------------------------------------------------------------------
void DNS_Server::replyWithError(DNSHeader *dnsHeader,
						 DNSReplyCode rcode,
						 unsigned char *query,
						 size_t queryLength)
{
	dnsHeader->QR = DNS_QR_RESPONSE;
	dnsHeader->RCode = (unsigned char) rcode;
	if (query)
		 dnsHeader->QDCount = lwip_htons(1);
	else
		 dnsHeader->QDCount = 0;
	dnsHeader->ANCount = 0;
	dnsHeader->NSCount = 0;
	dnsHeader->ARCount = 0;

	_udp.beginPacket(_udp.remoteIP(), _udp.remotePort());
	_udp.write((unsigned char *)dnsHeader, sizeof(DNSHeader));
	if (query != NULL)
		 _udp.write(query, queryLength);
	_udp.endPacket();
}

//-------------------------------------------------------------------------------
void DNS_Server::replyWithError(DNSHeader *dnsHeader,
						 DNSReplyCode rcode)
{
	replyWithError(dnsHeader, rcode, NULL, 0);
}

//-------------------------------------------------------------------------------
void DNS_Server::clearRecords()
{
	uint16_t i = 0;
	uint16_t j = 0;

	for( i = 0; i < MAX_DNS_RECORDS; i++ ){
		for( j = 0; j < MAX_DNSNAME_LENGTH; j++ ){
			_domainNames[ i ] [ j ] = '\0';
		}
	}

	for( i = 0; i < MAX_DNS_RECORDS; i++ ){
		for( j = 0; j < 4; j++ ){
			_resolvedIPs[ i ] [ j ] = 0;
		}
	}
}

//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
