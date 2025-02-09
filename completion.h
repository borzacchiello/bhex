#ifndef COMPLETION_H
#define COMPLETION_H

struct linenoiseCompletions;
struct CmdContext;

void  set_commands_for_completion(struct CmdContext* cc);
void  bhex_shell_completion(const char* buf, struct linenoiseCompletions* lc);
char* bhex_shell_hint(const char* buf, int* color, int* bold);

#endif
