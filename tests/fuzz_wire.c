#include "wire.h"

#include <stdint.h>
#include <stddef.h>

/* The parser must never read out of bounds or fail to terminate, whatever the
   input. Correctness of the parse is the unit test's job; this only asserts
   that no input crashes or hangs. Build with -fsanitize=fuzzer,address. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Reader     reader;
    WireHeader header;
    WireEdns   edns;

    (void)WireFindEdns(data, size, &edns);

    ReaderInit(&reader, data, size);
    if(WireParseHeader(&reader, &header))
    {
        WireQuestion question;
        while(WireParseQuestion(&reader, &question))
            ;

        ReaderInit(&reader, data, size);
        (void)ReaderSkip(&reader, WIRE_HEADER_BYTES);
        while(WireSkipRecord(&reader))
            ;
    }

    /* Names are also read from arbitrary offsets, since a hostile message can
       place a pointer anywhere in the payload. */
    for(size_t at = 0; at < size && at < 64; at++)
    {
        Reader   nameReader;
        WireName name;

        ReaderInit(&nameReader, data, size);
        if(ReaderSkip(&nameReader, at))
            (void)WireReadName(&nameReader, &name);
    }

    return 0;
}
