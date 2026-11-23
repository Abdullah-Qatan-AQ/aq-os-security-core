# انتقال AQ OS إلى Rust

أضيفت أول طبقة تنفيذية Rust إلى جانب نموذج Python المرجعي:

- `aqos-policy`: مكتبة `no_std` بلا تخصيص ذاكرة، تحتوي سياسة ترتيب مراحل الإقلاع، منع الرجوع، وقياس PCR باستخدام SHA-256 فعلي.
- `Ed25519Verifier`: تحقق توقيع فعلي لصيغة مراحل AQ OS (`name|version|SHA256(image)`).
- `kernel`: نواة `no_std` تستخدم `bootloader_api`، وتقلع عبر BIOS إلى VGA وserial.
- `image-builder`: ينتج صورة BIOS raw قابلة للإقلاع باستخدام bootloader مفتوح المصدر.
- `kernel/src/memory.rs`: مخصّص إطارات فيزيائية من خريطة الذاكرة التي يمررها bootloader.
- `kernel/src/heap.rs`: heap حقيقي بصفحات 4KiB و`LockedHeap` كمخصّص عام.
- `kernel/src/interrupts.rs`: IDT، استثناءات page fault وdouble fault، PIC 8259، ومقاطعة timer.
- `kernel/src/scheduler.rs`: round-robin task selection مرتبط بكل timer tick.
- `aqos-syscall`: ABI ثابت لـ syscalls، capabilities، والتحقق من مؤشرات user قبل dispatch.
- `kernel/src/address_space.rs`: جذور page tables مستقلة لمساحات user، خرائط `USER_ACCESSIBLE`، وحماية صفحات null.
- `AddressSpace::activate`: تبديل CR3 مع الاحتفاظ بخرائط kernel والعودة الآمنة إلى الجذر السابق.
- `kernel/src/gdt.rs`: GDT مع user code/data selectors وTSS ومكدس kernel لانتقالات ring3.

## البناء

```bash
cargo run -p aqos-image
cargo test -p aqos-policy
cargo run -p aqos-image -- --run
```

تم اختبار صورة BIOS فعليًا في QEMU، وظهرت الرسالة `AQ OS kernel: Rust bare-metal boot OK` عبر serial. ما يزال يلزم قبل نظام هاتف فعلي:

تم تنفيذ المرحلة الأولى الآن: تهيئة خريطة الذاكرة الفيزيائية، تخصيص إطارات usable، إنشاء صفحات heap، واختبار `Box` داخل النواة. يظهر في QEMU: `AQ OS kernel: memory manager OK`.

المرحلة الثانية منفذة: IDT وPIC، معالج timer، عداد ticks، ومعالج استثناءات، مع اختيار round-robin بين مهمتين مسجلتين. يظهر في QEMU: `AQ OS kernel: interrupts and timer OK`.

المرحلة الثالثة منفذة جزئيًا كطبقة ABI وعزل أولي: `ClockGetTicks` يتطلب `CLOCK_READ`، و`ConsoleWrite` يتطلب `CONSOLE_WRITE`، كما تُرفض المؤشرات الصفرية وخارج نطاق user أو النطاقات التي تتجاوز الحد. يثبت QEMU ذلك عبر الرسالة `AQ OS kernel: syscall capability gate OK`.

لم تُنفذ بعد حلقة دخول syscall عتادية أو ring 3 أو جداول صفحات user منفصلة أو محمّل ELF؛ لذلك لا ينبغي اعتبار هذه الطبقة عزل عمليات كاملًا.

المرحلة الرابعة منفذة كأساس MMU للعزل: يُنشأ root page table مستقل لكل مساحة، وتُخرط الصفحة الافتراضية نفسها في مساحتين بإطارين مختلفين. يثبت QEMU ذلك عبر `AQ OS kernel: isolated user address spaces OK`. لم يُفعّل تبديل `CR3` أو ring 3 بعد، ولا تزال خرائط kernel المشتركة ومحمّل ELF ومسار syscall العتادي ضمن المراحل اللاحقة.

المرحلة الخامسة منفذة: تُبنى مساحة بعنوان user مع خرائط kernel اللازمة، ويُختبر تبديل `CR3` بين مساحتين ثم استعادة جذر النواة. يثبت QEMU ذلك عبر `AQ OS kernel: user address spaces and CR3 switch OK`. ما يزال هذا تبديلًا بدائيًا للنواة، وليس تبديل سياق user كاملًا.

المرحلة السادسة منفذة جزئيًا: تهيئة GDT/TSS، إنشاء user code وuser stack، والانتقال إلى ring3 عبر `iretq`. يطلق البرنامج user `int3` عبر IDT ذات DPL3، ويثبت QEMU وصول trap من مستوى 3 عبر `AQ OS kernel: ring3 breakpoint trap OK`. لا يزال محمّل ELF، و`syscall/sysret`، وحفظ سجلات العمليات ضمن المراحل التالية.

1. boot protocol موثق مثل UEFI أو Multiboot2.
2. linker script وصورة disk/EFI قابلة للإقلاع.
3. إدارة ذاكرة وصفحات وMMU ومقاطعات وجدولة.
4. عزل عمليات فعلي وسواقات ومخزن دائم.
5. تشفير ومخزن مفاتيح عتادي وتحديث A/B.

لا تُستخدم هذه المرحلة لحماية بيانات حقيقية.
