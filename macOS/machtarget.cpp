/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <cstdlib>
#include <string.h>

#include <mach/mach_vm.h>
#include <mach-o/dyld_images.h>

#include "macOS/machtarget.h"
#include "common.h"

#define INVALID_PAGE_SIZE ((vm_size_t)(~0))

#ifdef ARM64
  #define ARCH_THREAD_STATE ARM_THREAD_STATE64
#else
  #define ARCH_THREAD_STATE x86_THREAD_STATE64
#endif

MachTarget::MachTarget(pid_t target_pid): pid(target_pid), m_page_size(INVALID_PAGE_SIZE) {
  kern_return_t krt;

  krt = task_for_pid(mach_task_self(), pid, &task);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) calling task_for_pid\n", mach_error_string(krt));
  }

  krt = task_get_exception_ports(task,
                                  EXC_MASK_ALL,
                                  saved_masks,
                                  &saved_exception_types_count,
                                  saved_ports,
                                  saved_behaviors,
                                  saved_flavors);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) saving the exception ports registered in the process\n", mach_error_string(krt));
  }

  krt = mach_port_allocate(mach_task_self(),
                           MACH_PORT_RIGHT_RECEIVE,
                           &exception_port);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) allocating a new port\n", mach_error_string(krt));
  }

  mach_port_insert_right(mach_task_self(),
                         exception_port,
                         exception_port,
                         MACH_MSG_TYPE_MAKE_SEND);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) authorizing a new exception port\n", mach_error_string(krt));
  }

  /* register the exception port with the target process */
  task_set_exception_ports(task,
                           EXC_MASK_ALL,
                           exception_port,
                           EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                           ARCH_THREAD_STATE);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) registering the exception port with the target process\n", mach_error_string(krt));
  }

}


kern_return_t MachTarget::BasicInfo(mach_task_basic_info *info) {
  if (info == NULL) {
    return KERN_INVALID_ARGUMENT;
  }

  unsigned int count = MACH_TASK_BASIC_INFO_COUNT;
  return task_info(task, MACH_TASK_BASIC_INFO, (task_info_t)info, &count);
}

bool MachTarget::IsExceptionPortValid() {
  return MACH_PORT_VALID(exception_port);
}


bool MachTarget::IsTaskValid() {
  if (task != TASK_NULL) {
    mach_task_basic_info task_info;
    return BasicInfo(&task_info) == KERN_SUCCESS;
  }

  return false;
}

void MachTarget::GetRegionSubmapInfo(mach_vm_address_t *region_address,
                                     mach_vm_size_t *region_size,
                                     vm_region_submap_info_data_64_t *info) {
  kern_return_t krt;
  uint32_t depth = ~0;
  mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
  krt = mach_vm_region_recurse(task,
                               region_address,
                               region_size,
                               &depth,
                               (vm_region_recurse_info_t)info,
                               &count);

  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) retrieving region information\n", mach_error_string(krt));
  }
}

kern_return_t MachTarget::WaitForException(uint32_t timeout, mach_msg_header_t *req, uint32_t size) {
  kern_return_t krt;
  krt = mach_msg(req,  /* receive buffer */
                 MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT,
                 0,                         /* size of send buffer */
                 size,                      /* size of receive buffer */
                 exception_port,            /* port to receive on */
                 timeout,                   /* wait for timeout seconds */
                 MACH_PORT_NULL);           /* notify port, unused */

  return krt;
}

void MachTarget::ReplyToException(mach_msg_header_t *rpl) {
  kern_return_t krt;
  krt = mach_msg(rpl,  /* send buffer */
                MACH_SEND_MSG | MACH_SEND_INTERRUPT,             /* send message */
                rpl->msgh_size,            /* size of send buffer */
                0,                         /* size of receive buffer */
                MACH_PORT_NULL,            /* port to receive on */
                MACH_MSG_TIMEOUT_NONE,     /* wait indefinitely */
                MACH_PORT_NULL);           /* notify port, unused */

  if (krt != MACH_MSG_SUCCESS) {
    FATAL("Error (%s) sending reply to exception port\n", mach_error_string(krt));
  }
}

void MachTarget::CleanUp() {
  /* restore saved exception ports */
  for (int i = 0; i < saved_exception_types_count; ++i) {
      task_set_exception_ports(task,
                               saved_masks[i],
                               saved_ports[i],
                               saved_behaviors[i],
                               saved_flavors[i]);
  }

  kern_return_t krt;
  krt = mach_port_destroy(mach_task_self(), exception_port);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) destroying exception port\n", mach_error_string(krt));
  }

  krt = mach_port_deallocate(mach_task_self(), task);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) deallocating task port", mach_error_string(krt));
  }

  task = TASK_NULL;
  exception_port = MACH_PORT_NULL;
}

void MachTarget::FreeMemory(uint64_t address, size_t size) {
  if (size == 0) {
    WARN("FreeMemory is called with size == 0\n");
    return;
  }

  kern_return_t krt = mach_vm_deallocate(task, (mach_vm_address_t)address, (mach_vm_size_t)size);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) freeing memory @ 0x%llx\n", mach_error_string(krt), address);
  }
}

void MachTarget::ReadMemory(uint64_t address, size_t size, void *buf) {
  if (buf == NULL) {
    WARN("ReadMemory is called with buf == NULL\n");
    return;
  }

  if (size == 0) {
    WARN("ReadMemory is called with size == 0\n");
    return;
  }

  kern_return_t krt;
  mach_vm_size_t total_bytes_read = 0;
  mach_vm_address_t cur_addr = address;
  uint8_t *cur_buf = (uint8_t*)buf;
  while (total_bytes_read < size) {
    mach_vm_size_t cur_size = MaxBytesLeftInPage(cur_addr, size - total_bytes_read);

    mach_msg_type_number_t cur_bytes_read = 0;
    vm_offset_t vm_buf;
    krt = mach_vm_read(task, cur_addr, cur_size, &vm_buf, &cur_bytes_read);

    if (krt != KERN_SUCCESS) {
      FATAL("Error (%s) reading memory @ address 0x%llx\n", mach_error_string(krt), cur_addr);
    }

    if (cur_bytes_read != cur_size) {
      FATAL("Error reading the entire requested memory @ address 0x%llx\n", cur_addr);
    }

    memcpy(cur_buf, (const void*)vm_buf, cur_bytes_read);
    mach_vm_deallocate(mach_task_self(), vm_buf, cur_bytes_read);

    total_bytes_read += cur_bytes_read;
    cur_addr += cur_bytes_read;
    cur_buf += cur_bytes_read;
  }
}

void MachTarget::WriteMemory(uint64_t address, const void *buf, size_t size) {
  if (buf == NULL) {
    WARN("WriteMemory is called with buf == NULL\n");
    return;
  }

  if (size == 0) {
    WARN("WriteMemory is called with size == 0\n");
    return;
  }

  uint64_t cur_address = address;
  while (cur_address < address + size) {
    mach_vm_address_t region_address = cur_address;
    mach_vm_size_t region_size = 0;
    vm_region_submap_info_data_64_t info;
    GetRegionSubmapInfo(&region_address, &region_size, &info);
    if (cur_address < region_address) {
      FATAL("Unable to write to unmapped memory region\n");
    }

    uint64_t cur_size = region_address + region_size - cur_address;
    if (cur_address + cur_size >= address + size) {
      cur_size = address + size - cur_address;
    }

    if (!(info.protection & VM_PROT_WRITE)) {
      kern_return_t krt = mach_vm_protect(task, cur_address, cur_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
      if (krt != KERN_SUCCESS) {
        ProtectMemory(cur_address, cur_size, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_WANTS_COPY);
      }
    }

    kern_return_t krt = mach_vm_write(task,
                                      (mach_vm_address_t)cur_address,
                                      (vm_offset_t)buf,
                                      (mach_msg_type_number_t)cur_size);
    if (krt != KERN_SUCCESS) {
      FATAL("Error (%s) writing memory @ 0x%llx\n", mach_error_string(krt), cur_address);
    }

    if (!(info.protection & VM_PROT_WRITE)) {
      ProtectMemory(cur_address, cur_size, info.protection);
    }

    buf = (void*)((uint64_t)buf + cur_size);
    cur_address += cur_size;
  }
}

void MachTarget::ProtectMemory(uint64_t address, uint64_t size, vm_prot_t protection) {
  if (size == 0) {
    WARN("ProtectMemory is called with size == 0\n");
    return;
  }

  kern_return_t krt = mach_vm_protect(task, address, size, false, protection);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) applying memory protection @ 0x%llx\n", mach_error_string(krt), address);
  }
}


size_t MachTarget::MaxBytesLeftInPage(mach_vm_address_t address, mach_vm_size_t size) {
  vm_size_t page_size = PageSize();
  if (page_size > 0) {
    mach_vm_size_t page_offset = address % page_size;
    mach_vm_size_t bytes_left_in_page = page_size - page_offset;
    if (size > bytes_left_in_page) {
      size = bytes_left_in_page;
    }
  }

  return size;
}

vm_size_t MachTarget::PageSize() {
  if (m_page_size == INVALID_PAGE_SIZE) {
    kern_return_t krt;

    task_vm_info_data_t vm_info;
    mach_msg_type_number_t info_count = TASK_VM_INFO_COUNT;
    krt = task_info(task, TASK_VM_INFO, (task_info_t)&vm_info, &info_count);

    if (krt != KERN_SUCCESS) {
      FATAL("Error (%s) retrieving target's TASK_VM_INFO\n", mach_error_string(krt));
    }

    m_page_size = vm_info.page_size;
  }

  return m_page_size;
}

dyld_all_image_infos MachTarget::GetAllImageInfos() {
  task_dyld_info_data_t task_dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

  kern_return_t krt;
  krt = task_info(task, TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
  if (krt != KERN_SUCCESS) {
    FATAL("Unable to retrieve task_info of target task, %d\n", krt);
  }

  dyld_all_image_infos all_image_infos;
  ReadMemory((uint64_t)task_dyld_info.all_image_info_addr, task_dyld_info.all_image_info_size, &all_image_infos);
  return all_image_infos;
}

void MachTarget::ReadCString(uint64_t address, size_t max_size, void *string) {
  while (max_size) {
    size_t cur_size = MaxBytesLeftInPage(address, max_size);
    ReadMemory(address, cur_size, string);
    if (memchr((void*)string, '\0', cur_size)) {
      return;
    }

    string = (void*)((uint64_t)string + cur_size);
    max_size -= cur_size;
    address += cur_size;
  }
}
