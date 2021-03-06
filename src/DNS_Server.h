#ifndef _DNS_Server_h
#define _DNS_Server_h

#include <WiFiUdp.h>

#define DNS_QR_QUERY 0
#define DNS_QR_RESPONSE 1
#define DNS_OPCODE_QUERY 0

#define DNS_QCLASS_IN 1
#define DNS_QCLASS_ANY 255

#define DNS_QTYPE_A 1
#define DNS_QTYPE_ANY 255

#define DNS_PORT					53
#define MAX_DNSNAME_LENGTH			64
#define MAX_DNS_PACKETSIZE			512
#ifndef MAX_DNS_RECORDS
	#define MAX_DNS_RECORDS			32
#endif

enum class DNSReplyCode
{
	NoError = 0,
	FormError = 1,
	ServerFailure = 2,
	NonExistentDomain = 3,
	NotImplemented = 4,
	Refused = 5,
	YXDomain = 6,
	YXRRSet = 7,
	NXRRSet = 8
};

struct DNSHeader
{
	uint16_t ID;               // identification number
	unsigned char RD : 1;      // recursion desired
	unsigned char TC : 1;      // truncated message
	unsigned char AA : 1;      // authoritative answer
	unsigned char OPCode : 4;  // message_type
	unsigned char QR : 1;      // query/response flag
	unsigned char RCode : 4;   // response code
	unsigned char Z : 3;       // its z! reserved
	unsigned char RA : 1;      // recursion available
	uint16_t QDCount;          // number of question entries
	uint16_t ANCount;          // number of answer entries
	uint16_t NSCount;          // number of authority entries
	uint16_t ARCount;          // number of resource entries
};

class DNS_Server
{
	public:
		DNS_Server();
		~DNS_Server() {
			stop();
		};

		void processNextRequest();
		void setErrorReplyCode(const DNSReplyCode &replyCode);
		void setTTL(const uint32_t &ttl);

		// Returns true if successful, false if there are no sockets available
		bool start(const uint16_t port = DNS_PORT);
		// stops the DNS server
		void stop();
		void addRecord(const char* domainName, const IPAddress &resolvedIP);
		/**
		 * find record in memory
		 * @param {char*} string whith '\0' at end or (returned -1)
		 * @return {int16_t} -1 if not found or position
		 */
		int16_t findRecord(const char* domainName, uint8_t length = MAX_DNSNAME_LENGTH);
		/**
		 * get DomainName for m_readIndx ( max: MAX_DNS_RECORDS )
		 * @param notching
		 * @return {const char*} constant pointer for data
		 */
		const char* getDomainName(void);
		/**	
		 * get Resolved IP for m_readIndx ( max: MAX_DNS_RECORDS )
		 * @param notching
		 * @return {const unsigned char*} constant pointer for data
		 */
		const unsigned char* getResolvedIP(void);
		/**
		 * get next Rule for m_readIndx ( max: MAX_DNS_RECORDS )
		 * @param notching
		 * @return {uint8_t} ( 0 if rules end )
		 */
		uint8_t nextRule(void);
		/**
		 * reset m_readIndx
		 * @param notching
		 * @return none
		 */
		void resetRulesIndex(void);
		/**
		 * set callback for new request
		 * @param {DNS_Server::HandlerFunction}
		 * @return none
		 */
		void newRequest(void (*func)(const char*, const uint8_t*));
		/**
		 * checking server running
		 * @return {uint8_t} ( 1 if server running, 0 if server stoped )
		 */
		uint8_t isRunning(void);
	private:
		WiFiUDP _udp;
		uint16_t _port;
		uint32_t _ttl;
		uint16_t m_readIndx;
		DNSReplyCode m_errorReplyCode;
		void (*m_pCallback)(const char*, const uint8_t*);
		char _domainNames[ MAX_DNS_RECORDS ] [ MAX_DNSNAME_LENGTH ];
		unsigned char _resolvedIPs[ MAX_DNS_RECORDS ] [ 4 ];
		uint8_t m_running;

		void downcaseAndRemoveWwwPrefix(String &domainName);
		void replyWithIP(DNSHeader *dnsHeader, unsigned char * query, size_t queryLength, unsigned char* ip);
		void replyWithError(DNSHeader *dnsHeader,
			DNSReplyCode rcode,
			unsigned char *query,
			size_t queryLength);
		void replyWithError(DNSHeader *dnsHeader,
			DNSReplyCode rcode);
		void respondToRequest(uint8_t *buffer, size_t length);
		void writeNBOShort(uint16_t value);
		void clearRecords();
};
#endif
