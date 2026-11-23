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
- `kernel/src/syscall_entry.rs`: تهيئة MSRs ومدخل assembly لـ `syscall` والعودة عبر `sysretq`.
- `kernel/src/elf.rs`: تحقق ELF64 وخرط قطاعات `PT_LOAD` داخل مساحة user.

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

المرحلة السابعة منفذة كأساس عتادي: تُفعّل MSRs الخاصة بـ `syscall/sysret`، ويستخدم المدخل assembly مكدسًا kernel عبر `swapgs`، يحفظ `RCX/R11`، يستدعي Rust، ثم يعيد التنفيذ إلى user. يثبت QEMU ذلك عبر `AQ OS kernel: hardware syscall entry OK`. يلزم لاحقًا ربطه بمدقق ABI وcapabilities وحفظ كامل للسجلات.

المرحلة الثامنة منفذة: محمل ELF64 يتحقق من الترويسة وجدول البرامج والحدود والمحاذاة، يخصص صفحات قطاعات `PT_LOAD` ويصفّر `memsz` وينسخ `filesz`، ثم يشغّل `e_entry` داخل ring3. يثبت QEMU ذلك عبر `AQ OS kernel: ELF user image loaded OK`.

1. boot protocol موثق مثل UEFI أو Multiboot2.
2. linker script وصورة disk/EFI قابلة للإقلاع.
3. إدارة ذاكرة وصفحات وMMU ومقاطعات وجدولة.
4. عزل عمليات فعلي وسواقات ومخزن دائم.
5. تشفير ومخزن مفاتيح عتادي وتحديث A/B.

لا تُستخدم هذه المرحلة لحماية بيانات حقيقية.

## المرحلة التاسعة: عمليات user وتبديل السياق

أضيف `kernel/src/process.rs` لإدارة PCB ثابتة الحجم. كل PCB يحتفظ بمعرّف العملية، حالتها، `AddressSpace`، `e_entry`، وقمة مكدس user. حمّلت النواة ELF الاختبارية مرتين في مساحتي عناوين منفصلتين، مع إطار code وإطار stack مستقلين لكل عملية.

أصبح syscall رقم `Yield` يستدعي `process::yield_next`: يختار العملية التالية القابلة للتشغيل، يحدّث الحالات، ويستدعي `AddressSpace::activate` لتبديل `CR3` قبل عودة `sysretq`. أثبت QEMU الانتقال من العملية الأولى إلى الثانية ثم استمرار syscall العتادي، مع بقاء الاختبارات السابقة ناجحة.

النطاق الحالي تعاوني ومحدود للتحقق: لم يُنفّذ بعد حفظ كل السجلات العامة، أو جدولة preemptive كاملة من timer، أو إنهاء العملية والإشارات، أو مكدس syscall مستقل لكل CPU. لذلك لا تُعد هذه المرحلة نظام عمليات إنتاجيًا مكتملًا.

## المرحلة العاشرة: preemption عبر timer

أضيف `process::preempt_next` لاختيار العملية التالية وتفعيل `CR3` من مسار مقاطعة المؤقت. إذا كان إطار المقاطعة عائدًا إلى ring3، يحدّث معالج timer إطار `iretq` إلى `e_entry` ومكدس العملية التالية، مع اختبار QEMU مستقل يثبت الرسالة `AQ OS kernel: timer preemptive user switch OK` ثم استمرار breakpoint وsyscall.

النطاق الحالي preemption عند نقطة العودة فقط؛ لا يدّعي حفظ كل سجلات GPR أو استئناف العملية من نفس التعليمة، ولا يزال ذلك مطلوبًا لجدولة إنتاجية كاملة.
