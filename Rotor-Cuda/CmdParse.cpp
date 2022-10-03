#include "CmdParse.h"
#include <iostream>     // std::cout
#include <fstream>      // std::ifstream
#include "Rotor.h"
std::string stroka2 = "";


CmdParse::CmdParse()
{

}

void CmdParse::add(const std::string shortForm, bool hasArg)
{
	this->add(shortForm, "", hasArg);
}

void CmdParse::add(const std::string shortForm, const std::string longForm, bool hasArg)
{
	ArgType arg;
	arg.shortForm = shortForm;
	arg.longForm = longForm;
	arg.hasArg = hasArg;

	_argType.push_back(arg);
}

bool CmdParse::get(const std::string opt, ArgType& t)
{
	for (unsigned int i = 0; i < _argType.size(); i++) {
		if (_argType[i].shortForm == opt || _argType[i].longForm == opt) {
			t = _argType[i];
			return true;
		}
	}

	return false;
}

void CmdParse::parse(int argc, char** argv)
{
	std::string nos2 = "Rotor-Cuda.exe";
	for (int i = 1; i < argc; i++) {
		std::string arg(argv[i]);

		ArgType t;
		if (get(arg, t)) {
			// It is an option

			OptArg a;

			if (t.hasArg) {
				// It requires an argument

				if (i == argc - 1) {
					throw std::string("'" + arg + "' requires an argument");
				}

				std::string optArg(argv[i + 1]);
				i++;
				a.option = arg;
				a.arg = optArg;

			}
			else {
				// It does not require an argument
				a.option = arg;
				a.arg = "";
			}
			
			if (a.arg == "") {
				nos2 = nos2 + " " + a.option;
			}
			else {
				nos2 = nos2 + " " + a.option + " " + a.arg;
			}
			_optArgs.push_back(a);
		}
		else {
			// It is an operand
			_operands.push_back(arg);
			nos2 = nos2 + " " + arg.c_str();
		}
	}
	
	std::ifstream file777("Rotor-Cuda_Continue.bat");
	std::string s777;
	std::string kogda;
	for (int i = 0; i < 5; i++) {
		getline(file777, s777);
		if (i == 4) {
			stroka2 = s777;
		}
	}
	
	if (stroka2 == "") {
		FILE* ptrFile = fopen("Rotor-Cuda_START.bat", "w+");
		fprintf(ptrFile, ":loop \n");
		fprintf(ptrFile, "%s \n", nos2.c_str());
		fprintf(ptrFile, "goto :loop \n");
		fprintf(ptrFile, "\n");
		fclose(ptrFile);
	}
	else {
		std::string pusto = "";
	}
}

std::vector<OptArg> CmdParse::getArgs()
{
	return _optArgs;
}

std::vector<std::string> CmdParse::getOperands()
{
	return _operands;
}