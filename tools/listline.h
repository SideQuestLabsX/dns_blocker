#ifndef DNS_BLOCKER_LISTLINE_H
#define DNS_BLOCKER_LISTLINE_H

/* One list line to one name. Shared by the generator and its test, because the
   sources disagree on format: a bare domain, a hosts entry with an address in
   front, and a wildcard rule are all in use. */

#include <ctype.h>
#include <stddef.h>
#include <string.h>

/* Why a line carried no name. A source that contributes nothing looks the same
   as a comment block unless the refusals are counted apart. */
typedef enum
{
    ListLine_Name,
    ListLine_Blank,
    ListLine_NoDot,
    ListLine_Wildcard
} ListLineReason;

static inline const char *ListLineReasonName(ListLineReason reason)
{
    switch(reason)
    {
        case ListLine_Name:     return "name";
        case ListLine_Blank:    return "blank or comment";
        case ListLine_NoDot:    return "no dot";
        case ListLine_Wildcard: return "wildcard inside the name";
    }

    return "unknown";
}

/* Rewrites line in place and returns the name, or NULL when the line carries
   none. `why` may be NULL. */
static inline char *ListLineNameWhy(char *line, ListLineReason *why)
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

    if(len == 0)
    {
        if(why != NULL)
            *why = ListLine_Blank;
        return NULL;
    }

    if(strchr(name, '.') == NULL)
    {
        if(why != NULL)
            *why = ListLine_NoDot;
        return NULL;
    }

    /* A wildcard anywhere else is a rule this format cannot express. */
    if(strchr(name, '*') != NULL)
    {
        if(why != NULL)
            *why = ListLine_Wildcard;
        return NULL;
    }

    if(why != NULL)
        *why = ListLine_Name;

    return name;
}

static inline char *ListLineName(char *line)
{
    return ListLineNameWhy(line, NULL);
}

#endif
