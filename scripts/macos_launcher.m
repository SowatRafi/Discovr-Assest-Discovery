// Finder launches this small native app; the bundled engine then replaces this
// process. No shell, installer, downloaded runtime or temporary extraction is used.
#import <Cocoa/Cocoa.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    @autoreleasepool {
        NSString *engine = [[[NSBundle mainBundle] resourcePath]
            stringByAppendingPathComponent:@"runtime/Discovr"];
        // The desktop has no command-line modes. Always start the bundled engine
        // without arguments, including when LaunchServices supplies its own flags.
        char *arguments[] = {(char *)[engine fileSystemRepresentation], NULL};
        execv(arguments[0], arguments);

        int failure = errno;
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Discovr could not start";
        alert.informativeText = [NSString stringWithFormat:
            @"Keep the complete Discovr app together on your drive.\n\n%s", strerror(failure)];
        [alert runModal];
        return 1;
    }
}
