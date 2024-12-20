#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/sched/signal.h>
#include <linux/utsname.h>
#include <linux/jiffies.h>
#include <linux/sysinfo.h>
#include <linux/cpu.h>
#include <linux/mm.h>

#define DEVICE_NAME "kfetch"
#define KFETCH_NUM_INFO 6

#define KFETCH_RELEASE   (1 << 0)
#define KFETCH_NUM_CPUS  (1 << 1)
#define KFETCH_CPU_MODEL (1 << 2)
#define KFETCH_MEM       (1 << 3)
#define KFETCH_UPTIME    (1 << 4)
#define KFETCH_NUM_PROCS (1 << 5)

#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SamYang");
MODULE_DESCRIPTION("A kernel module to fetch system information");

#define KFETCH_BUF_MAX_SIZE 4096
#define LINE_WIDTH 128

static int major_num;
static char *kfetch_buf;
static size_t kfetch_buf_size;
static int info_mask = KFETCH_FULL_INFO; // Default to show all information
static DEFINE_MUTEX(kfetch_mutex); // Use mutex to make sure the safety in multi-thread environment

static const char *logo[] = {
    "                   ",
    "        .-.        ",
    "       (.. |       ",
    "       <>  |       ",
    "      / --- \\      ",
    "     ( |   | )     ",
    "   |\\\\_)__(_//|   ",
    "  <__)------(__>   "
};

#define LOGO_HEIGHT (sizeof(logo) / sizeof(logo[0]))
#define LOGO_WIDTH 20   // Fixed logo width for alignment

// Set the info_mask as modinfo which can be modified when inserting this kernel module or after insmod
module_param(info_mask, int, 0644);
MODULE_PARM_DESC(info_mask, "Bitmask for selecting displayed information");

static void kfetch_generate_info(void) {
    char info_lines[LOGO_HEIGHT][LINE_WIDTH];
    int line_i = 0;
    size_t buf_offset = 0;
    struct sysinfo mem_info;
    struct task_struct *task;
    int proc_count = 0;
    char hostname[65];
    struct cpuinfo_x86 c;
    unsigned int cpu = 0;
    struct timespec64 uptime;
    unsigned long freeram_mb;
    unsigned long totalram_mb;
    
    kfree(kfetch_buf); // Make sure the previous time allocation has been cleaned up
    kfetch_buf = kzalloc(KFETCH_BUF_MAX_SIZE, GFP_KERNEL);
    if (!kfetch_buf) {
        pr_alert("kfetch_generate_info: Failed to allocate buffer\n");
        mutex_unlock(&kfetch_mutex);
        return;
    }

    /* Get hostname */
    snprintf(hostname, sizeof(hostname), "%s", utsname()->nodename);
    snprintf(info_lines[line_i++], LINE_WIDTH, "%s", hostname);
    snprintf(info_lines[line_i++], LINE_WIDTH, "%.*s", (int)strlen(hostname), "---------------------"); // generate seperation line with hostname length

    /* Fetch information */
    if (info_mask & KFETCH_RELEASE)
        snprintf(info_lines[line_i++], LINE_WIDTH, "Kernel:   %s", utsname()->release);

    if (info_mask & KFETCH_CPU_MODEL) {
        c = cpu_data(cpu);
        snprintf(info_lines[line_i++], sizeof(info_lines[0]), "CPU:      %s", c.x86_model_id);
    }

    if (info_mask & KFETCH_NUM_CPUS)
        snprintf(info_lines[line_i++], LINE_WIDTH, "CPUs:     %d / %d", num_online_cpus(), num_present_cpus());

    if (info_mask & KFETCH_MEM) {
        si_meminfo(&mem_info);
        // Consider mem_unit to accurately transform mem size
        freeram_mb = (mem_info.freeram * mem_info.mem_unit) >> 20;
        totalram_mb = (mem_info.totalram * mem_info.mem_unit) >> 20;

        snprintf(info_lines[line_i++], LINE_WIDTH, "Mem:      %lu MB / %lu MB", freeram_mb, totalram_mb);
    }

    if (info_mask & KFETCH_NUM_PROCS) {
        for_each_process(task)
            proc_count++;
        snprintf(info_lines[line_i++], LINE_WIDTH, "Procs:    %d", proc_count);
    }

    if (info_mask & KFETCH_UPTIME) {
        ktime_get_boottime_ts64(&uptime);
        snprintf(info_lines[line_i++], LINE_WIDTH, "Uptime:   %lu minutes", (unsigned long)uptime.tv_sec / 60);
    }

    /* Put the logo at the left side of the message */
    for (int i = 0; i < LOGO_HEIGHT; i++) {
        const char *logo_line = logo[i];        // Get the current line content of logo
        const char *info_line = (i < line_i) ? info_lines[i] : ""; // Avoid exceeding the valid line number

        // Splice logo and info into kfetch_buf
        buf_offset += snprintf(kfetch_buf + buf_offset, KFETCH_BUF_MAX_SIZE - buf_offset,
                               "%-*s %s\n", LOGO_WIDTH, logo_line, info_line); // %-*s left aligned width
    }
    kfetch_buf_size = buf_offset;
}

static ssize_t kfetch_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset) {
    if (*offset >= kfetch_buf_size) // Check if the end of reading is reached
        return 0;
    
    if (length > kfetch_buf_size - *offset) // Ensure we don't read beyond the buffer size
        length = kfetch_buf_size - *offset;

    if (copy_to_user(buffer, kfetch_buf + *offset, length))
        return -EFAULT;

    *offset += length;
    return length;
}

static ssize_t kfetch_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset) {
    int new_mask;

    if (copy_from_user(&new_mask, buffer, length))
        return -EFAULT;
    
    pr_info("kfetch_write: new_mask = %d, length = %d\n", new_mask, length);

    if (length > 0) {
        if (new_mask < 0 || new_mask > KFETCH_FULL_INFO) {
            pr_err("Invalid mask value: %d\n", new_mask);
            return -EINVAL; // Ensure mask is in a valid range
        }
        info_mask = new_mask;
        pr_info("kfetch_write: info_mask updated = %d\n", info_mask);
    }

    kfetch_generate_info();
    return length;
}

static int kfetch_open(struct inode *inode, struct file *file) {
    pr_info("kfetch_open: trying to acquire mutex\n");
    if (!mutex_trylock(&kfetch_mutex)) {
        pr_info("kfetch_open: failed to acquire mutex\n");
        return -EBUSY;
    }
    pr_info("kfetch_open: acquired mutex\n");
    return 0;
}

static int kfetch_release(struct inode *inode, struct file *file) {
    pr_info("kfetch_release: releasing mutex\n");
    mutex_unlock(&kfetch_mutex);
    return 0;
}

static struct file_operations kfetch_ops = {
    .owner = THIS_MODULE, // Avoid kernel crash caused by unloading modules during use
    .read = kfetch_read,
    .write = kfetch_write,
    .open = kfetch_open,
    .release = kfetch_release,
};

static int __init kfetch_init(void) {
    major_num = register_chrdev(0, DEVICE_NAME, &kfetch_ops);
    if (major_num < 0) {
        pr_alert("kfetch: failed to register device\n");
        return major_num;
    }
    pr_info("kfetch: registered with major number %d\n", major_num);
    kfetch_generate_info();
    return 0;
}

static void __exit kfetch_exit(void) {
    unregister_chrdev(major_num, DEVICE_NAME);
    kfree(kfetch_buf);
    pr_info("kfetch: module unloaded\n");
}

module_init(kfetch_init);
module_exit(kfetch_exit);
