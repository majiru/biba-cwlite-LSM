/*
* Sample LSM implementation
*/

//#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
//#include <linux/smp_lock.h>
#include <linux/hardirq.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/kd.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/debugfs.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for sysctl_local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <asm/uaccess.h>
//#include <asm/semaphore.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <asm/uaccess.h>
// Added by Chris
#include <linux/cred.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/lsm_hooks.h>
// End


static void initfs(void);

MODULE_LICENSE("GPL");

#define INITCONTEXTLEN 100
#define XATTR_SAMPLE_SUFFIX "sample"
#define XATTR_NAME_SAMPLE XATTR_SECURITY_PREFIX XATTR_SAMPLE_SUFFIX

#define PATHLEN 128

#define SAMPLE_IGNORE 0
#define SAMPLE_UNTRUSTED 1
#define SAMPLE_TRUSTED 2
#define SAMPLE_TARGET_SID 7

/* Mask definitions */
#define MAY_EXEC 1
#define MAY_READ 4
#define MAY_APPEND 8
#define MAY_WRITE 2
#define MAY_WRITE_EXEC 3


extern struct security_operations *security_ops;
/*
* Minimal support for a secondary security module,
* just to allow the use of the capability module.
*/
//static struct security_operations *secondry_ops;


/* Convert context string to sid value (SAMPLE_*) */

static int security_context_to_sid(char *context, u32 *sid)
{
#if 0
	printk(KERN_WARNING "%s: have context: %s\n",
	       __FUNCTION__, context);
#endif

	if (!context) return -1;

	if (strcmp(context, "untrusted") == 0) {
		*sid = SAMPLE_UNTRUSTED;
#if 1
		printk(KERN_WARNING "%s: have UN-Trusted context: %s\n",
		       __FUNCTION__, context);
#endif
	}
	else if (strcmp(context, "trusted") == 0) {
		*sid = SAMPLE_TRUSTED;
#if 1
		printk(KERN_WARNING "%s: have Trusted context: %s\n",
		       __FUNCTION__, context);
#endif
	}
	else if (strcmp(context, "target") == 0)
		*sid = SAMPLE_TARGET_SID;
	else 
		*sid = SAMPLE_IGNORE;

#if 0
	printk(KERN_WARNING "%s: have sid: 0x%x\n",
	       __FUNCTION__, *sid);
#endif

	return 0;
}

static void cred_init_security(void)
{
	struct cred *cred = (struct cred *) current->real_cred;
	//struct task_security_struct *tsec;

	/*
	MODIFIED: Everything else here seems to use a u32 casted
	void pointer for the value, so let's fix that here.
	Also changed to see if this was causing kmem_cache_alloc
	panics on boot: it was not but let's leave this supposed fix
	in here for the previous reasoning.
	tsec = kzalloc(sizeof(struct task_security_struct), GFP_KERNEL);
	if (!tsec)
		panic("Sample:  Failed to initialize initial task.\n");

	tsec->sid = 1;
	*/
	cred->security = 1;
}

static int has_perm(u32 ssid_full, u32 osid, u32 ops)
{
	u32 cwl = 0xf0000000 & ssid_full;
	u32 ssid = 0xfffffff & ssid_full;

	if(ssid && osid){
		//Prevent write
		if((ops & MAY_WRITE) || (ops & MAY_APPEND))
		if((ssid == SAMPLE_UNTRUSTED) && (osid == SAMPLE_TRUSTED))
			return 1;

		//Prevent read
		if((ops & MAY_READ) || (ops & MAY_EXEC))
		if((ssid == SAMPLE_TRUSTED && osid == SAMPLE_UNTRUSTED))
		if(!cwl)
			return 2;

		//Everything checks out OK
		return 0;
	}

	//Don't block procs that we don't manage	
	return 0;
}


static u32 inode_init_with_dentry(struct dentry *dentry, struct inode *inode)
{
	int len, rc;
	char *context;
	u32 sid;

	//if (!inode->i_op->getxattr) {
	if (!inode->i_sb->s_xattr) {
		goto out;
	}

/* Need a dentry, since the xattr API requires one.
   Life would be simpler if we could just pass the inode. */

	if (!dentry) {
//		printk(KERN_WARNING "%s:  no dentry for dev=%s "
//		       "ino=%ld\n", __FUNCTION__, inode->i_sb->s_id,
//		       inode->i_ino);
		goto out;
	}

	len = INITCONTEXTLEN;
	context = kmalloc(len, GFP_KERNEL);
	if (!context) {
		dput(dentry);
		printk(KERN_WARNING "%s: kmalloc error exit\n",
		       __FUNCTION__);
		goto out;
	}
	/*rc = inode->i_op->getxattr(dentry, XATTR_NAME_SAMPLE,
				   context, len);
	*/
	rc = __vfs_getxattr(dentry, inode, XATTR_NAME_SAMPLE, context, len);
	len = rc;
	if (rc == -ERANGE) {
		/* Need a larger buffer.  Query for the right size. */
		rc = __vfs_getxattr(dentry, inode, XATTR_NAME_SAMPLE, NULL, 0);
		/*rc = inode->i_op->getxattr(dentry, XATTR_NAME_SAMPLE,
					   NULL, 0);*/
		if (rc < 0) {
			dput(dentry);
			kfree(context);
			goto out;
		}
		kfree(context);
		len = rc;
		context = kmalloc(len, GFP_KERNEL);
		if (!context) {
			rc = -ENOMEM;
			dput(dentry);
			printk(KERN_WARNING "%s: no mem error exit\n",
			       __FUNCTION__);
			goto out;
		}
		/*rc = inode->i_op->getxattr(dentry,
					   XATTR_NAME_SAMPLE,
					   context, len);*/
		rc = __vfs_getxattr(dentry, inode, XATTR_NAME_SAMPLE, context, len);
	}
	dput(dentry);
	if (rc < 0) {
		kfree(context);
		goto out;
	} else {
		/* not always null terminated at length */
		context[len] = '\0';
		/* We have a legit context */
		rc = security_context_to_sid(context, &sid);
#if 0
		printk(KERN_WARNING "%s:  context_to_sid(%s:%d) "
		       "returned 0x%x for dev=%s ino=%ld\n",
		       __FUNCTION__, context, len, sid,
		       inode->i_sb->s_id, inode->i_ino);
#endif
		if (rc) {
#if 0
			printk(KERN_WARNING "%s:  context_to_sid(%s) "
			       "returned %d for dev=%s ino=%ld\n",
			       __FUNCTION__, context, -rc,
			       inode->i_sb->s_id, inode->i_ino);
#endif
			/* Leave with the unlabeled SID */
			sid = SAMPLE_IGNORE;
		}
	}
	kfree(context);
	return sid;

out:
	return SAMPLE_IGNORE;
}


static u32 get_task_sid(struct task_struct *task)
{
	return (u32) task->cred->security;
}


static u32 get_inode_sid(struct inode *inode)
{
	struct dentry *dentry;

	dentry = d_find_alias(inode); 
	return inode_init_with_dentry(dentry, inode);
}


static int inode_has_perm(struct task_struct *task, 
		  struct inode *inode, int ops)//,
		  //struct vfsmount *mnt, struct dentry *dentry)
{
	u32 ssid = get_task_sid(task);
	u32 osid = get_inode_sid(inode);
	int rtn = 0;
	char *pname = (char *)NULL;
	char *buf = NULL;
	int len = PATHLEN;

/* get pathname for exceptions and printing */
	/* buf = kmalloc(len, GFP_KERNEL);
	if(!buf){
		panic("Failed to alloc buf for inode_has_perm");
	}
	*/

	//if (buf && dentry && mnt) {  // && nd->dentry && nd->mnt
	if(buf) {
		buf = memset(buf, '\0', len);
		//pname = d_path(dentry, mnt, buf, len-1);
		// YOUR WORK: Should it be fd[0]?
		//pname = d_path(&(task->files->fdt->fd[0]->f_path), buf, len-1);
		pname = NULL;
		
#if 0
		if (ssid && osid) {
			printk(KERN_WARNING "%s: path: 0x%x with val %s; buf 0x%x with val %s\n",
			       __FUNCTION__, pname, pname, buf, buf); 
		}
#endif
	}

/* exceptions */
	/*
	if (pname && (len >= 4)) {
		if (!strncmp(buf, "/dev", 4))  // allow /dev
			goto done;
		if (!strncmp(buf, "/proc", 5)) // allow /proc
			goto done;
		if (!strncmp(buf, "/var", 4)) // allow /var - no xattr
			goto done;
	}
	*/

/* YOUR CODE: do authorize */
/* DONE */
	rtn = has_perm(ssid, osid, ops);

/* Then, use this code to print relevant denials: for our processes or on our objects */
	if (( ssid && osid ) && rtn ) {
		printk(KERN_WARNING "%s: task pid=%d of ssid 0x%x "
		       "NOT authorized (%d) for inode osid 0x%x (file:%s) for ops 0x%x\n",
		       __FUNCTION__, current->pid, ssid, rtn, osid, 
		       (pname ? pname : "unk?"), ops);
}

/* Then, use this code to print relevant authorizations: for our processes */
	if (( ssid && osid ) &&
	    ( !rtn )) {
		printk(KERN_WARNING "%s: target task pid=%d of ssid 0x%x "
		       "authorized for inode osid:ops 0x%x:0x%x (file:%s) \n",
		       __FUNCTION__, current->pid, ssid, osid, ops, 
		       (pname ? pname : "unk?"));
	}

done:
	if(buf){
		kfree(buf);
	}
	return rtn;
}


static int sample_inode_permission(struct inode *inode, int mask)
			   //struct nameidata *nd)
{
	//struct vfsmount *mnt = (struct vfsmount *)NULL;
	//struct dentry *dentry = (struct dentry *)NULL;
	int rtn;

/* no need to check if no mask (ops) */
	if (!mask) {
		/* No permission to check.  Existence test. */
		return 0;
	}

	/* get the dentry for inode_has_perm */
	/*if ( nd ) {  
		mnt = nd->path.mnt;
		dentry = nd->path.dentry;
	}*/

#if 0
	if ( current->cred->security ) {  // ssid
		printk(KERN_WARNING "%s: file path info: mnt: 0x%x; dentry 0x%x\n",
		       __FUNCTION__, mnt, dentry);
	}
#endif

	//rtn = inode_has_perm(current, inode, mask, mnt, dentry);
	rtn = inode_has_perm(current, inode, mask);

	return 0; /* permissive */
}



/* Label process based on xattr of executable file */

//static int sample_bprm_set_security(struct linux_binprm *bprm)
static int sample_bprm_set_creds(struct linux_binprm *bprm)
{
	struct inode *inode = file_inode(bprm->file);
	struct cred *cred = (struct cred *) current->real_cred;
	/* YOUR CODE: Determine the osid and label for the new process */
	/* DONE? */
	int osid = 1;

	osid = get_inode_sid(bprm->file->f_path.dentry->d_inode);
/* if the inode's sid indicates trusted or untrusted, then set 
   task->security */
	if (osid) {
		cred->security = (void *)osid;
		printk(KERN_WARNING "%s: set task pid=%d of ssid 0x%x\n",
		       __FUNCTION__, current->pid, osid);
	}

	return 0;
}

static int has_done_debugfs_init = 0;


static int sample_inode_init_security(struct inode *inode, struct inode *dir,
			       const struct qstr *qstr, const char **name, void** value,
			       size_t *len)
{
	u32 ssid = get_task_sid(current);
	u32 actual_ssid = 0xfffffff & ssid;
	char *namep, *valuep;


	/* Ok so, creating the debugfs in the init is
	not allowed because it uses malloc, which we can't use
	at the time so instead let's try doing it only once 
	somewhere else.
	Race conditions: yes.
	Bad design: yes  */
	if(has_done_debugfs_init == 0){
		initfs();
		has_done_debugfs_init = 1;
	}

	if (!inode || !dir)
		return -EOPNOTSUPP;

	if (actual_ssid == SAMPLE_IGNORE)
		return -EOPNOTSUPP;

	printk(KERN_WARNING "%s: pid %d:0x%x creating a new file\n",
	       __FUNCTION__, current->pid, ssid);

/* get attribute name */
	namep = kstrdup(XATTR_SAMPLE_SUFFIX, GFP_KERNEL);
	if (!namep)
		return -ENOMEM;
	*name = namep;

/* set xattr value and length */
	if (actual_ssid == SAMPLE_TRUSTED) {
		valuep = kstrdup("trusted", GFP_KERNEL);
		*len = 8;
		printk(KERN_WARNING "%s: task pid=%d of ssid 0x%x creates Trusted object\n",
		       __FUNCTION__, current->pid, actual_ssid);
	}
	else if (actual_ssid == SAMPLE_UNTRUSTED) {
		valuep = kstrdup("untrusted", GFP_KERNEL);
		*len = 10;
		printk(KERN_WARNING "%s: task pid=%d of ssid 0x%x creates UN-Trusted object\n",
		       __FUNCTION__, current->pid, actual_ssid);
	}

	if (!valuep)
		return -ENOMEM;
	*value = valuep;

	return 0;
}


static int sample_inode_setxattr (struct dentry *dentry, const char *name, const void *value,
				      size_t size, int flags)
{
	struct inode *inode;
	u32 mask = MAY_WRITE;
	struct vfsmount *mnt = (struct vfsmount *)NULL;
	u32 ssid, osid;
	int rtn;

	if (!strncmp(name, XATTR_NAME_SAMPLE,
		     sizeof(XATTR_NAME_SAMPLE) - 1)) {
		// sample ignores these
		return 0;
	}

	if (!dentry || !dentry->d_inode) {
		return -EPERM;
	}

	/* YOUR CODE: Gather inputs for inode_has_perm */
	/* DONE */
	inode = dentry->d_inode;
	ssid = get_task_sid(current);
	osid = get_inode_sid(inode);

/* record attribute setting request before authorization */
	if (ssid && osid) {
		printk(KERN_WARNING "%s: task pid=%d of label 0x%x setting attribute %s"
		       "for object of label 0x%x\n",
		       __FUNCTION__, current->pid, ssid, (name ? name : "unk?"), osid);
	}

	//rtn = inode_has_perm(current, inode, mask, mnt, dentry);
	rtn = inode_has_perm(current, inode, mask);

	return 0;
}


static int sample_inode_create (struct inode *inode, struct dentry *dentry,
                               umode_t mask)
{
	u32 ssid = get_task_sid(current);
	u32 osid;

	if (!inode) {
		printk(KERN_WARNING "%s: no inode created by task of ssid 0x%x\n",
		       __FUNCTION__, ssid);
		return 0;
	}

	osid = get_inode_sid(inode);

	if (ssid == SAMPLE_UNTRUSTED) {
		printk(KERN_WARNING "%s: untrusted task pid=%d with sid 0x%x" 
			" creating file %s of sid 0x%x\n",
		       __FUNCTION__, current->pid, ssid, "filename", osid);
	}

        return 0;
}


int sample_file_permission (struct file *file, int mask)
{
        struct inode *inode;
	struct vfsmount *mnt = (struct vfsmount *)NULL;
	struct dentry *dentry = (struct dentry *)NULL;
	int rtn;

	/* no need to check if no mask (ops) */
        if (!mask) {
                /* No permission to check.  Existence test. */
		return 0;
        }

	/* NULL file */
	if (!file || !file->f_path.dentry) {
		printk(KERN_WARNING "%s: no file by task of pid 0x%x\n",
		       __FUNCTION__, current->pid);
		return 0;
	}

	/* YOUR CODE: Collect arguments for call to inode_has_perm */
	/* DONE */
	inode = file->f_path.dentry->d_inode;

	if ( current->cred->security ) {  // ssid
#if 0
		printk(KERN_WARNING "%s: file path info: mnt: 0x%x; dentry 0x%x\n",
		       __FUNCTION__, mnt, dentry);
#endif
	}

	//rtn = inode_has_perm(current, inode, mask, mnt, dentry);
	rtn = inode_has_perm(current, inode, mask);

	return 0; /* permissive */
}


static struct security_hook_list sample_ops[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(inode_permission, sample_inode_permission),
	//.bprm_set_security =		sample_bprm_set_security,
	LSM_HOOK_INIT(bprm_set_creds, sample_bprm_set_creds),
	LSM_HOOK_INIT(inode_init_security, sample_inode_init_security),
	LSM_HOOK_INIT(inode_setxattr, sample_inode_setxattr),
	LSM_HOOK_INIT(inode_create, sample_inode_create),
	LSM_HOOK_INIT(file_permission, sample_file_permission),
#if 0
	.ptrace_access_check =		selinux_ptrace_access_check,
	.ptrace_traceme =		selinux_ptrace_traceme,
	.capget =			selinux_capget,
	.capset =			selinux_capset,
	.sysctl =			selinux_sysctl,
	.capable =			selinux_capable,
	.quotactl =			selinux_quotactl,
	.quota_on =			selinux_quota_on,
	.syslog =			selinux_syslog,
	.vm_enough_memory =		selinux_vm_enough_memory,

	.netlink_send =			selinux_netlink_send,
	.netlink_recv =			selinux_netlink_recv,

	.bprm_set_creds =		selinux_bprm_set_creds,
	.bprm_committing_creds =	selinux_bprm_committing_creds,
	.bprm_committed_creds =		selinux_bprm_committed_creds,
	.bprm_secureexec =		selinux_bprm_secureexec,

	.sb_alloc_security =		selinux_sb_alloc_security,
	.sb_free_security =		selinux_sb_free_security,
	.sb_copy_data =			selinux_sb_copy_data,
	.sb_kern_mount =		selinux_sb_kern_mount,
	.sb_show_options =		selinux_sb_show_options,
	.sb_statfs =			selinux_sb_statfs,
	.sb_mount =			selinux_mount,
	.sb_umount =			selinux_umount,
	.sb_set_mnt_opts =		selinux_set_mnt_opts,
	.sb_clone_mnt_opts =		selinux_sb_clone_mnt_opts,
	.sb_parse_opts_str = 		selinux_parse_opts_str,


	.inode_alloc_security =		selinux_inode_alloc_security,
	.inode_free_security =		selinux_inode_free_security,
	.inode_init_security =		selinux_inode_init_security,
	.inode_create =			selinux_inode_create,
	.inode_link =			selinux_inode_link,
	.inode_unlink =			selinux_inode_unlink,
	.inode_symlink =		selinux_inode_symlink,
	.inode_mkdir =			selinux_inode_mkdir,
	.inode_rmdir =			selinux_inode_rmdir,
	.inode_mknod =			selinux_inode_mknod,
	.inode_rename =			selinux_inode_rename,
	.inode_readlink =		selinux_inode_readlink,
	.inode_follow_link =		selinux_inode_follow_link,
	.inode_permission =		selinux_inode_permission,
	.inode_setattr =		selinux_inode_setattr,
	.inode_getattr =		selinux_inode_getattr,
	.inode_setxattr =		selinux_inode_setxattr,
	.inode_post_setxattr =		selinux_inode_post_setxattr,
	.inode_getxattr =		selinux_inode_getxattr,
	.inode_listxattr =		selinux_inode_listxattr,
	.inode_removexattr =		selinux_inode_removexattr,
	.inode_getsecurity =		selinux_inode_getsecurity,
	.inode_setsecurity =		selinux_inode_setsecurity,
	.inode_listsecurity =		selinux_inode_listsecurity,
	.inode_getsecid =		selinux_inode_getsecid,

	.file_permission =		selinux_file_permission,
	.file_alloc_security =		selinux_file_alloc_security,
	.file_free_security =		selinux_file_free_security,
	.file_ioctl =			selinux_file_ioctl,
	.file_mmap =			selinux_file_mmap,
	.file_mprotect =		selinux_file_mprotect,
	.file_lock =			selinux_file_lock,
	.file_fcntl =			selinux_file_fcntl,
	.file_set_fowner =		selinux_file_set_fowner,
	.file_send_sigiotask =		selinux_file_send_sigiotask,
	.file_receive =			selinux_file_receive,

	.dentry_open =			selinux_dentry_open,

	.task_create =			selinux_task_create,
	.cred_alloc_blank =		selinux_cred_alloc_blank,
	.cred_free =			selinux_cred_free,
	.cred_prepare =			selinux_cred_prepare,
	.cred_transfer =		selinux_cred_transfer,
	.kernel_act_as =		selinux_kernel_act_as,
	.kernel_create_files_as =	selinux_kernel_create_files_as,
	.kernel_module_request =	selinux_kernel_module_request,
	.task_setpgid =			selinux_task_setpgid,
	.task_getpgid =			selinux_task_getpgid,
	.task_getsid =			selinux_task_getsid,
	.task_getsecid =		selinux_task_getsecid,
	.task_setnice =			selinux_task_setnice,
	.task_setioprio =		selinux_task_setioprio,
	.task_getioprio =		selinux_task_getioprio,
	.task_setrlimit =		selinux_task_setrlimit,
	.task_setscheduler =		selinux_task_setscheduler,
	.task_getscheduler =		selinux_task_getscheduler,
	.task_movememory =		selinux_task_movememory,
	.task_kill =			selinux_task_kill,
	.task_wait =			selinux_task_wait,
	.task_to_inode =		selinux_task_to_inode,

	.ipc_permission =		selinux_ipc_permission,
	.ipc_getsecid =			selinux_ipc_getsecid,

	.msg_msg_alloc_security =	selinux_msg_msg_alloc_security,
	.msg_msg_free_security =	selinux_msg_msg_free_security,

	.msg_queue_alloc_security =	selinux_msg_queue_alloc_security,
	.msg_queue_free_security =	selinux_msg_queue_free_security,
	.msg_queue_associate =		selinux_msg_queue_associate,
	.msg_queue_msgctl =		selinux_msg_queue_msgctl,
	.msg_queue_msgsnd =		selinux_msg_queue_msgsnd,
	.msg_queue_msgrcv =		selinux_msg_queue_msgrcv,

	.shm_alloc_security =		selinux_shm_alloc_security,
	.shm_free_security =		selinux_shm_free_security,
	.shm_associate =		selinux_shm_associate,
	.shm_shmctl =			selinux_shm_shmctl,
	.shm_shmat =			selinux_shm_shmat,

	.sem_alloc_security =		selinux_sem_alloc_security,
	.sem_free_security =		selinux_sem_free_security,
	.sem_associate =		selinux_sem_associate,
	.sem_semctl =			selinux_sem_semctl,
	.sem_semop =			selinux_sem_semop,

	.d_instantiate =		selinux_d_instantiate,

	.getprocattr =			selinux_getprocattr,
	.setprocattr =			selinux_setprocattr,

	.secid_to_secctx =		selinux_secid_to_secctx,
	.secctx_to_secid =		selinux_secctx_to_secid,
	.release_secctx =		selinux_release_secctx,
	.inode_notifysecctx =		selinux_inode_notifysecctx,
	.inode_setsecctx =		selinux_inode_setsecctx,
	.inode_getsecctx =		selinux_inode_getsecctx,

	.unix_stream_connect =		selinux_socket_unix_stream_connect,
	.unix_may_send =		selinux_socket_unix_may_send,

	.socket_create =		selinux_socket_create,
	.socket_post_create =		selinux_socket_post_create,
	.socket_bind =			selinux_socket_bind,
	.socket_connect =		selinux_socket_connect,
	.socket_listen =		selinux_socket_listen,
	.socket_accept =		selinux_socket_accept,
	.socket_sendmsg =		selinux_socket_sendmsg,
	.socket_recvmsg =		selinux_socket_recvmsg,
	.socket_getsockname =		selinux_socket_getsockname,
	.socket_getpeername =		selinux_socket_getpeername,
	.socket_getsockopt =		selinux_socket_getsockopt,
	.socket_setsockopt =		selinux_socket_setsockopt,
	.socket_shutdown =		selinux_socket_shutdown,
	.socket_sock_rcv_skb =		selinux_socket_sock_rcv_skb,
	.socket_getpeersec_stream =	selinux_socket_getpeersec_stream,
	.socket_getpeersec_dgram =	selinux_socket_getpeersec_dgram,
	.sk_alloc_security =		selinux_sk_alloc_security,
	.sk_free_security =		selinux_sk_free_security,
	.sk_clone_security =		selinux_sk_clone_security,
	.sk_getsecid =			selinux_sk_getsecid,
	.sock_graft =			selinux_sock_graft,
	.inet_conn_request =		selinux_inet_conn_request,
	.inet_csk_clone =		selinux_inet_csk_clone,
	.inet_conn_established =	selinux_inet_conn_established,
	.req_classify_flow =		selinux_req_classify_flow,
	.tun_dev_create =		selinux_tun_dev_create,
	.tun_dev_post_create = 		selinux_tun_dev_post_create,
	.tun_dev_attach =		selinux_tun_dev_attach,

#ifdef CONFIG_SECURITY_NETWORK_XFRM
	.xfrm_policy_alloc_security =	selinux_xfrm_policy_alloc,
	.xfrm_policy_clone_security =	selinux_xfrm_policy_clone,
	.xfrm_policy_free_security =	selinux_xfrm_policy_free,
	.xfrm_policy_delete_security =	selinux_xfrm_policy_delete,
	.xfrm_state_alloc_security =	selinux_xfrm_state_alloc,
	.xfrm_state_free_security =	selinux_xfrm_state_free,
	.xfrm_state_delete_security =	selinux_xfrm_state_delete,
	.xfrm_policy_lookup =		selinux_xfrm_policy_lookup,
	.xfrm_state_pol_flow_match =	selinux_xfrm_state_pol_flow_match,
	.xfrm_decode_session =		selinux_xfrm_decode_session,
#endif

#ifdef CONFIG_KEYS
	.key_alloc =			selinux_key_alloc,
	.key_free =			selinux_key_free,
	.key_permission =		selinux_key_permission,
	.key_getsecurity =		selinux_key_getsecurity,
#endif

#ifdef CONFIG_AUDIT
	.audit_rule_init =		selinux_audit_rule_init,
	.audit_rule_known =		selinux_audit_rule_known,
	.audit_rule_match =		selinux_audit_rule_match,
	.audit_rule_free =		selinux_audit_rule_free,
#endif

#endif /* sample if 0 */
};

static struct dentry *cwl_debugfs_root;
static struct dentry *d_cwl;
static struct dentry *d_cwlite;

static ssize_t cwlite_read(struct file *filp, char __user *buffer, 
				size_t count, loff_t *ppos)
{
	char states[] = {'0', '1'};
	short state_i = 0;
	/* YOUR CODE: for reading the CW-Lite value from the kernel */
	/* DONE */
	struct cred *cred = (struct cred *) current->real_cred;	
	if( ((u32)0x10000000 & (u32)cred->security) > 0){
		state_i = 1;
	}
	copy_to_user(buffer, states+state_i, 1);	

	return 1;
}


static ssize_t cwlite_write(struct file *filp, const char __user *buffer,
                                 size_t count, loff_t *ppos)
{
        char new_value;
	struct cred *cred = (struct cred *) current->real_cred;
	/* YOUR CODE: for collecting value to write from user space */
	/* MODIFICATION: the original code uses characters 0 and 1, this code uses the integer
	   Change this to the char that the user writes */
	/* DONE */
	copy_from_user(&new_value, buffer, 1);	

        // get current
        // set flag on task
        switch (new_value) {
        case '0':
                cred->security = (void *)(0xfffffff & (u32)cred->security);
                printk(KERN_INFO "sample: New security setting (0): pid=%d, sec=0x%x\n", 
				current->pid, (unsigned int) cred->security);
                break;
        case '1':
                cred->security = (void *)(0x10000000 | (u32)cred->security);
                printk(KERN_INFO "sample: New security setting (1): pid=%d, sec=0x%x\n", 
				current->pid, (unsigned int) cred->security);
                break;
        default:
                printk(KERN_INFO "%s: invalid CW-Lite value %d\n",
                        __FUNCTION__, new_value);
		return -EINVAL;
		break;
        }

out:
        return 1;
}


static struct file_operations cwlite_ops = {
	.owner = THIS_MODULE,
	.read = cwlite_read,
	.write = cwlite_write,
};


static void initfs(void)
{

	cwl_debugfs_root = debugfs_create_dir("cwl", NULL);
        if (!cwl_debugfs_root) {
        	printk(KERN_INFO "Sample: Creating debugfs 'cwl' dir failed\n");
                return -ENOENT;
	}

	/* YOUR CODE: Create debugfs file "cwlite" under "cwl" directory */
	/* DONE */
	d_cwl = debugfs_create_file("cwlite", 0644, cwl_debugfs_root, NULL, &cwlite_ops);
	if(d_cwl < 0){
		printk(KERN_INFO "Sample: Could not create cwlite file\n");
		return -ENOENT;
	}

        printk(KERN_INFO "Sample:  Debugfs created: cwl: 0x%x, cwlite: 0x%x.\n",
		cwl_debugfs_root, d_cwl);
}


static int __init sample_init(void)
{	
	security_add_hooks(sample_ops, ARRAY_SIZE(sample_ops), "cwlite");
        //if (register_security (&sample_ops)) {
        //        printk(KERN_INFO "Sample: Unable to register with kernel.\n");
        //        return 0;
        //}

        printk(KERN_INFO "Sample:  Initializing.\n");

	/* Set the security state for the initial task. */
	cred_init_security();


        return 0;
}

DEFINE_LSM(cwlite_info) = {
	.name = "cwlite",
	.init = sample_init,
};

