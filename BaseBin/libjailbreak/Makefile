TARGET = libjailbreak.dylib

CC = clang

CFLAGS = -framework Foundation -framework CoreServices -framework Security -framework IOKit -framework IOSurface -I../.include -I../_external/modules/litehook/src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -dynamiclib -install_name @loader_path/$(TARGET) -I$(shell brew --prefix)/opt/libarchive/include -g
LDFLAGS = -larchive -lbsm -L../.build -lchoma

sign: $(TARGET)
	@ldid -S $<

$(TARGET): $(wildcard src/*.c src/*.m src/*.S ../_external/modules/litehook/src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
