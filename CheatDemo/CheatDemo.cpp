#include <iostream>
#include "Process.h"

int main()
{
    // encontra o processo do jogo
    Process* game = new Process("ac_client.exe");
    game->Open();

    // determina o endereço base e o endereço alvo
    BYTE* baseAddress = game->mainModule.modBaseAddr;
    BYTE* targetAddress = baseAddress + 0xC73EF;

    // salva as intruções antes de sobrescrever
    BYTE oldBytes[2];
    game->ReadMemory(targetAddress, oldBytes, 2, true);

    // sobrescreve as intruções com NOPs
    BYTE nops[] = "\x90\x90";
    game->WriteMemory(targetAddress, nops, 2, true);

    std::cout << "Cheat enabled!\n";
    std::cin.get();

    // restaura as instruções
    game->WriteMemory(targetAddress, oldBytes, 2, true);

    std::cout << "Cheat disabled!\n";
    std::cin.get();

    // cleanup
    game->Close();
    delete game;
}