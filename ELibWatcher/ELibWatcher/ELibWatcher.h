#pragma once

class ELibWatcher
{
public:
public:
	ELibWatcher();
	~ELibWatcher();
public:
	static ELibWatcher& Instance();

	void InitELibWatcher();
};