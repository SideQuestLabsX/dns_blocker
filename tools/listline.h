#ifndef DNS_BLOCKER_LISTLINE_H
#define DNS_BLOCKER_LISTLINE_H

/* One list line to one name. Shared by the generator and its test, because the
   sources disagree on format: a bare domain, a hosts entry with an address in
   front, and a wildcard rule are all in use. */

#include <ctype.h>
#include <stddef.h>
#include <string.h>

/* Rewrites line in place and returns the name, or NULL when the line carries
   none. */
static inline char *ListLineName(char *line)
{
    char *at = strchr(line, '#');
    if(at != NULL)
        *at = '\0';

    for(char *c = line; *c != '\0'; c++)
    {
        if(*c == '\r' || *c == '\n')
            *c = '\0';
        else
            *c = (char)tolower((unsigned char)*c);
    }

    char *name = line;
    while(*name == ' ' || *name == '\t')
        name++;

    /* Trimmed before the field split, or a line that ended in a comment leaves
       trailing blanks and the last field is empty. */
    size_t end = strlen(name);
    while(end > 0 && (name[end - 1] == ' ' || name[end - 1] == '\t'))
    {
        end--;
        name[end] = '\0';
    }

    /* A hosts line puts an address first. Take the last field. */
    char *space = strrchr(name, ' ');
    if(space == NULL)
        space = strrchr(name, '\t');
    if(space != NULL)
        name = space + 1;

    /* An entry already covers every name below it, so a wildcard rule loses
       its prefix. Splitting on the dot instead makes `*` a label, which blocks
       the literal name and nothing else. */
    while(name[0] == '*' && name[1] == '.')
        name += 2;

    size_t len = strlen(name);
    while(len > 0 && name[len - 1] == '.')
    {
        name[len - 1] = '\0';
        len--;
    }

    if(len == 0 || strchr(name, '.') == NULL)
        return NULL;

    /* A wildcard anywhere else is a rule this format cannot express. */
    if(strchr(name, '*') != NULL)
        return NULL;

    return name;
}

#endif
