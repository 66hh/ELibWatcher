#pragma once
#include <string>
#include <vector>

class FastSearchPattern
{
	struct MatchRule
	{
		unsigned char bytes[16];
		int byteLen;
		std::uint32_t mask;
	};
public:
	FastSearchPattern(std::string pattern);
	~FastSearchPattern();
	int searchOne(void* pBuffer, size_t bufSize);
	std::vector<size_t> searchAll(void* pBuffer, size_t bufSize);
private:
	unsigned char firstSig;
	//ÌØÕ÷Âë³¤¶È
	unsigned int sigLen;
	std::vector<MatchRule> ruleList;
};