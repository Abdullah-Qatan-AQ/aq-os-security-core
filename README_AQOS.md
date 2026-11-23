
## المرحلة التاسعة: عمليات user وتبديل السياق التعاوني

تم تنفيذ `kernel/src/process.rs` كمدير عمليات ثابت الحجم يحتوي PCB لكل عملية user، مع الحالة (`Runnable`/`Running`/`Exited`)، مساحة العنوان، نقطة الدخول، ومؤشر مكدس user. تُحمّل صورة ELF نفسها في مساحتين مستقلتين مع صفحات code وstack فيزيائية مختلفة، وتُسجّل العمليتان قبل دخول ring3.

يرتبط syscall `Yield` الآن بمدير العمليات: يختار العملية التالية round-robin، يحدّث الحالة، ويبدّل `CR3` فعليًا داخل مسار `syscall` قبل `sysretq`. يختبر برنامج user ذلك باستدعاء `Yield` ثم syscall عتادي ثانٍ، ويثبت QEMU الرسائل `AQ OS kernel: user process context switch OK` و`AQ OS kernel: hardware syscall entry OK` دون page fault أو double fault أو panic.

هذا تنفيذ لبداية إدارة العمليات وتبديل مساحة العنوان التعاوني، وليس جدولة preemptive كاملة بعد: لا يحفظ مدخل syscall جميع السجلات العامة، ولا توجد بعد عملية خروج user أو إشارات أو مكدس syscall مستقل لكل CPU أو استعادة سياق timer كاملة. هذه العناصر تبقى ضمن المراحل اللاحقة.
