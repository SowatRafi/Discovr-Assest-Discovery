// Finder launches this small native app; the bundled engine then replaces this
// process. No shell, installer, downloaded runtime or temporary extraction is used.
#import <Cocoa/Cocoa.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSString *engine = [[[NSBundle mainBundle] resourcePath]
            stringByAppendingPathComponent:@"runtime/Discovr"];
        // Preserve support/test arguments as separate values; USB paths may have spaces.
        argv[0] = (char *)[engine fileSystemRepresentation];
        execv(argv[0], argv);

        int failure = errno;
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Discovr could not start";
        alert.informativeText = [NSString stringWithFormat:
            @"Keep the complete Discovr app together on your drive.\n\n%s", strerror(failure)];
        [alert runModal];
        return 1;
    }
}
