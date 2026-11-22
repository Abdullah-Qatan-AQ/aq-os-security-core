# انتقال AQ OS إلى Rust

أضيفت أول طبقة تنفيذية Rust إلى جانب نموذج Python المرجعي:

- `aqos-policy`: مكتبة `no_std` بلا تخصيص ذاكرة، تحتوي سياسة ترتيب مراحل الإقلاع، منع الرجوع، وقياس PCR باستخدام SHA-256 فعلي.
- `Ed25519Verifier`: تحقق توقيع فعلي لصيغة مراحل AQ OS (`name|version|SHA256(image)`).
- `kernel`: نواة `no_std` تستخدم `bootloader_api`، وتقلع عبر BIOS إلى VGA وserial.
- `image-builder`: ينتج صورة BIOS raw قابلة للإقلاع باستخدام bootloader مفتوح المصدر.
- `kernel/src/memory.rs`: مخصّص إطارات فيزيائية من خريطة الذاكرة التي يمررها bootloader.
- `kernel/src/heap.rs`: heap حقيقي بصفحات 4KiB و`LockedHeap` كمخصّص عام.

## البناء

```bash
cargo run -p aqos-image
cargo test -p aqos-policy
cargo run -p aqos-image -- --run
```

تم اختبار صورة BIOS فعليًا في QEMU، وظهرت الرسالة `AQ OS kernel: Rust bare-metal boot OK` عبر serial. ما يزال يلزم قبل نظام هاتف فعلي:

تم تنفيذ المرحلة الأولى الآن: تهيئة خريطة الذاكرة الفيزيائية، تخصيص إطارات usable، إنشاء صفحات heap، واختبار `Box` داخل النواة. يظهر في QEMU: `AQ OS kernel: memory manager OK`.

1. boot protocol موثق مثل UEFI أو Multiboot2.
2. linker script وصورة disk/EFI قابلة للإقلاع.
3. إدارة ذاكرة وصفحات وMMU ومقاطعات وجدولة.
4. عزل عمليات فعلي وسواقات ومخزن دائم.
5. تشفير ومخزن مفاتيح عتادي وتحديث A/B.

لا تُستخدم هذه المرحلة لحماية بيانات حقيقية.
