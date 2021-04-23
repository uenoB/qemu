/*
 * QEMU Hypervisor.framework support
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "sysemu/hvf.h"
#include "sysemu/hvf_int.h"
#include "sysemu/runstate.h"
#include "exec/address-spaces.h"

#include "qemu/main-loop.h"
#include "qemu/accel.h"

bool hvf_allowed;
HVFState *hvf_state;

void assert_hvf_ok(hv_return_t ret)
{
    if (ret == HV_SUCCESS) {
        return;
    }

    switch (ret) {
    case HV_ERROR:
        error_report("Error: HV_ERROR");
        break;
    case HV_BUSY:
        error_report("Error: HV_BUSY");
        break;
    case HV_BAD_ARGUMENT:
        error_report("Error: HV_BAD_ARGUMENT");
        break;
    case HV_NO_RESOURCES:
        error_report("Error: HV_NO_RESOURCES");
        break;
    case HV_NO_DEVICE:
        error_report("Error: HV_NO_DEVICE");
        break;
    case HV_UNSUPPORTED:
        error_report("Error: HV_UNSUPPORTED");
        break;
    default:
        error_report("Unknown Error");
    }

    abort();
}

#ifdef __aarch64__
#define HV_VM_DEFAULT NULL
#endif

/* Memory slots */

struct mac_slot {
    int present;
    uint64_t size;
    uint64_t gpa_start;
    uint64_t gva;
};

hvf_slot *hvf_find_overlap_slot(uint64_t start, uint64_t size)
{
    hvf_slot *slot;
    int x;
    for (x = 0; x < hvf_state->num_slots; ++x) {
        slot = &hvf_state->slots[x];
        if (slot->size && start < (slot->start + slot->size) &&
            (start + size) > slot->start) {
            return slot;
        }
    }
    return NULL;
}

struct mac_slot mac_slots[32];

static int do_hvf_set_memory(hvf_slot *slot, hv_memory_flags_t flags)
{
    struct mac_slot *macslot;
    hv_return_t ret;

    macslot = &mac_slots[slot->slot_id];

    if (macslot->present) {
        if (macslot->size != slot->size) {
            macslot->present = 0;
            ret = hv_vm_unmap(macslot->gpa_start, macslot->size);
            assert_hvf_ok(ret);
        }
    }

    if (!slot->size) {
        return 0;
    }

    macslot->present = 1;
    macslot->gpa_start = slot->start;
    macslot->size = slot->size;
    ret = hv_vm_map(slot->mem, slot->start, slot->size, flags);
    assert_hvf_ok(ret);
    return 0;
}

static void hvf_set_phys_mem(MemoryRegionSection *section, bool add)
{
    hvf_slot *mem;
    MemoryRegion *area = section->mr;
    bool writeable = !area->readonly && !area->rom_device;
    hv_memory_flags_t flags;

    if (!memory_region_is_ram(area)) {
        if (writeable) {
            return;
        } else if (!memory_region_is_romd(area)) {
            /*
             * If the memory device is not in romd_mode, then we actually want
             * to remove the hvf memory slot so all accesses will trap.
             */
             add = false;
        }
    }

    mem = hvf_find_overlap_slot(
            section->offset_within_address_space,
            int128_get64(section->size));

    if (mem && add) {
        if (mem->size == int128_get64(section->size) &&
            mem->start == section->offset_within_address_space &&
            mem->mem == (memory_region_get_ram_ptr(area) +
            section->offset_within_region)) {
            return; /* Same region was attempted to register, go away. */
        }
    }

    /* Region needs to be reset. set the size to 0 and remap it. */
    if (mem) {
        mem->size = 0;
        if (do_hvf_set_memory(mem, 0)) {
            error_report("Failed to reset overlapping slot");
            abort();
        }
    }

    if (!add) {
        return;
    }

    if (area->readonly ||
        (!memory_region_is_ram(area) && memory_region_is_romd(area))) {
        flags = HV_MEMORY_READ | HV_MEMORY_EXEC;
    } else {
        flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
    }

    /* Now make a new slot. */
    int x;

    for (x = 0; x < hvf_state->num_slots; ++x) {
        mem = &hvf_state->slots[x];
        if (!mem->size) {
            break;
        }
    }

    if (x == hvf_state->num_slots) {
        error_report("No free slots");
        abort();
    }

    mem->size = int128_get64(section->size);
    mem->mem = memory_region_get_ram_ptr(area) + section->offset_within_region;
    mem->start = section->offset_within_address_space;
    mem->region = area;

    if (do_hvf_set_memory(mem, flags)) {
        error_report("Error registering new memory slot");
        abort();
    }
}

static void hvf_set_dirty_tracking(MemoryRegionSection *section, bool on)
{
    hvf_slot *slot;

    slot = hvf_find_overlap_slot(
            section->offset_within_address_space,
            int128_get64(section->size));

    /* protect region against writes; begin tracking it */
    if (on) {
        slot->flags |= HVF_SLOT_LOG;
        hv_vm_protect((uintptr_t)slot->start, (size_t)slot->size,
                      HV_MEMORY_READ);
    /* stop tracking region*/
    } else {
        slot->flags &= ~HVF_SLOT_LOG;
        hv_vm_protect((uintptr_t)slot->start, (size_t)slot->size,
                      HV_MEMORY_READ | HV_MEMORY_WRITE);
    }
}

static void hvf_log_start(MemoryListener *listener,
                          MemoryRegionSection *section, int old, int new)
{
    if (old != 0) {
        return;
    }

    hvf_set_dirty_tracking(section, 1);
}

static void hvf_log_stop(MemoryListener *listener,
                         MemoryRegionSection *section, int old, int new)
{
    if (new != 0) {
        return;
    }

    hvf_set_dirty_tracking(section, 0);
}

static void hvf_log_sync(MemoryListener *listener,
                         MemoryRegionSection *section)
{
    /*
     * sync of dirty pages is handled elsewhere; just make sure we keep
     * tracking the region.
     */
    hvf_set_dirty_tracking(section, 1);
}

static void hvf_region_add(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    hvf_set_phys_mem(section, true);
}

static void hvf_region_del(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    hvf_set_phys_mem(section, false);
}

static MemoryListener hvf_memory_listener = {
    .priority = 10,
    .region_add = hvf_region_add,
    .region_del = hvf_region_del,
    .log_start = hvf_log_start,
    .log_stop = hvf_log_stop,
    .log_sync = hvf_log_sync,
};

static int hvf_accel_init(MachineState *ms)
{
    int x;
    hv_return_t ret;
    HVFState *s;

    ret = hv_vm_create(HV_VM_DEFAULT);
    assert_hvf_ok(ret);

    s = g_new0(HVFState, 1);

    s->num_slots = 32;
    for (x = 0; x < s->num_slots; ++x) {
        s->slots[x].size = 0;
        s->slots[x].slot_id = x;
    }

    hvf_state = s;
    memory_listener_register(&hvf_memory_listener, &address_space_memory);
    return 0;
}

static void hvf_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    ac->name = "HVF";
    ac->init_machine = hvf_accel_init;
    ac->allowed = &hvf_allowed;
}

static const TypeInfo hvf_accel_type = {
    .name = TYPE_HVF_ACCEL,
    .parent = TYPE_ACCEL,
    .class_init = hvf_accel_class_init,
};

static void hvf_type_init(void)
{
    type_register_static(&hvf_accel_type);
}

type_init(hvf_type_init);
