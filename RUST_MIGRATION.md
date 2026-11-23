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

1. boot protocol موثق مثل UEFI أو Multiboot2.
2. linker script وصورة disk/EFI قابلة للإقلاع.
3. إدارة ذاكرة وصفحات وMMU ومقاطعات وجدولة.
4. عزل عمليات فعلي وسواقات ومخزن دائم.
5. تشفير ومخزن مفاتيح عتادي وتحديث A/B.

لا تُستخدم هذه المرحلة لحماية بيانات حقيقية.
