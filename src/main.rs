#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::UNIX_EPOCH;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, HKEY,
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ,
    REG_MULTI_SZ, REG_QWORD, REG_SZ, REG_VALUE_TYPE,
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ChangeKind {
    Added,
    Modified,
}

impl ChangeKind {
    fn label(&self) -> &'static str {
        match self {
            ChangeKind::Added => "[+ ДОБАВЛЕНО]",
            ChangeKind::Modified => "[~ ИЗМЕНЕНО]",
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TargetType {
    File,
    Directory,
    RegistryKey,
    RegistryValue,
}

impl TargetType {
    fn label(&self) -> &'static str {
        match self {
            TargetType::File => "Файл",
            TargetType::Directory => "Папка",
            TargetType::RegistryKey => "Раздел реестра",
            TargetType::RegistryValue => "Параметр реестра",
        }
    }
}

#[derive(Clone)]
struct TrackedChange {
    kind: ChangeKind,
    target: TargetType,
    path: String,
    details: String,
}

#[derive(Default)]
struct SystemSnapshot {
    // Путь -> (размер_в_байтах, время_модификации_сек)
    files: HashMap<String, (u64, u64)>,
    dirs: BTreeSet<String>,
    // Путь раздела реестра -> время последней записи (FILETIME u64)
    reg_keys: HashMap<String, u64>,
    // "Путь_раздела\Имя_параметра" -> строковое представление значения
    reg_values: HashMap<String, String>,
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

fn should_skip_dir(path: &Path) -> bool {
    let low = path.to_string_lossy().to_lowercase();
    // Исключаем системный шум, кэши браузеров и временные файлы Windows
    low.contains(r"\windows\winsxs")
        || low.contains(r"\windows\servicing")
        || low.contains(r"\windows\temp")
        || low.contains(r"\windows\prefetch")
        || low.contains(r"\windows\softwaredistribution")
        || low.contains(r"\windows\logs")
        || low.contains(r"\appdata\local\temp")
        || low.contains(r"\appdata\local\microsoft\windows\inetcache")
        || low.contains(r"\appdata\local\microsoft\windows\webcache")
        || low.contains(r"\appdata\local\packages")
        || low.contains(r"\appdata\local\google\chrome\user data")
        || low.contains(r"\appdata\local\bravesoftware\brave-browser\user data")
        || low.contains(r"\appdata\local\mozilla\firefox\profiles")
        || low.ends_with(r"\$recycle.bin")
        || low.ends_with(r"\system volume information")
}

fn scan_fs_recursive(dir: &Path, snap: &mut SystemSnapshot) {
    if should_skip_dir(dir) {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };

    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };

        if meta.is_dir() {
            if !should_skip_dir(&path) {
                snap.dirs.insert(path.to_string_lossy().to_string());
                scan_fs_recursive(&path, snap);
            }
        } else if meta.is_file() {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            snap.files
                .insert(path.to_string_lossy().to_string(), (meta.len(), mtime));
        }
    }
}

fn scan_reg_recursive(
    root: HKEY,
    root_name: &str,
    subkey: &str,
    depth: usize,
    snap: &mut SystemSnapshot,
) {
    if depth > 12 {
        return;
    }

    let sub_w = to_wide(subkey);
    let mut hkey = HKEY::default();
    if unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR(sub_w.as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        )
    }
    .is_err()
    {
        return;
    }

    let mut subkey_count = 0u32;
    let mut value_count = 0u32;
    let mut last_write = FILETIME::default();

    let info_ok = unsafe {
        RegQueryInfoKeyW(
            hkey,
            PWSTR::null(),
            None,
            None,
            Some(&mut subkey_count),
            None,
            None,
            Some(&mut value_count),
            None,
            None,
            None,
            Some(&mut last_write),
        )
    }
    .is_ok();

    let full_key_path = format!(r"{}\{}", root_name, subkey);
    if info_ok {
        snap.reg_keys
            .insert(full_key_path.clone(), filetime_to_u64(last_write));
    }

    // Читаем параметры внутри раздела
    for idx in 0..value_count {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let mut data_buf = [0u8; 2048];
        let mut data_len = data_buf.len() as u32;
        let mut reg_type = 0u32;

        if unsafe {
            RegEnumValueW(
                hkey,
                idx,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                Some(&mut reg_type),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            )
        }
        .is_ok()
        {
            let val_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let display_name = if val_name.is_empty() {
                "(Default)".to_string()
            } else {
                val_name
            };

            let vt = REG_VALUE_TYPE(reg_type);
            let val_str = if vt == REG_SZ || vt == REG_EXPAND_SZ || vt == REG_MULTI_SZ {
                let u16s: Vec<u16> = data_buf[..data_len as usize]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&u16s)
                    .trim_end_matches('\0')
                    .replace('\0', " ")
            } else if vt == REG_DWORD && data_len >= 4 {
                let n = u32::from_le_bytes([data_buf[0], data_buf[1], data_buf[2], data_buf[3]]);
                format!("0x{:08X} ({})", n, n)
            } else if vt == REG_QWORD && data_len >= 8 {
                let n = u64::from_le_bytes([
                    data_buf[0], data_buf[1], data_buf[2], data_buf[3], data_buf[4], data_buf[5],
                    data_buf[6], data_buf[7],
                ]);
                format!("0x{:016X} ({})", n, n)
            } else {
                format!("<binary {} bytes>", data_len)
            };

            snap.reg_values
                .insert(format!(r"{}\{}", full_key_path, display_name), val_str);
        }
    }

    // Рекурсивно обходим подразделы
    for idx in 0..subkey_count {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        if unsafe {
            RegEnumKeyExW(
                hkey,
                idx,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                PWSTR::null(),
                None,
                None,
            )
        }
        .is_ok()
        {
            let child_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let child_sub = format!(r"{}\{}", subkey, child_name);
            scan_reg_recursive(root, root_name, &child_sub, depth + 1, snap);
        }
    }

    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

fn take_snapshot() -> SystemSnapshot {
    let mut snap = SystemSnapshot::default();

    // 1. Основные директории установки программ и конфигов
    let mut target_dirs = vec![
        PathBuf::from(r"C:\Program Files"),
        PathBuf::from(r"C:\Program Files (x86)"),
    ];
    if let Ok(progdata) = env::var("ProgramData") {
        target_dirs.push(PathBuf::from(progdata));
    }
    if let Ok(appdata) = env::var("APPDATA") {
        target_dirs.push(PathBuf::from(appdata));
    }
    if let Ok(localappdata) = env::var("LOCALAPPDATA") {
        target_dirs.push(PathBuf::from(localappdata));
    }

    for dir in target_dirs {
        scan_fs_recursive(&dir, &mut snap);
    }

    // 2. Основные ветки реестра программ и автозагрузки
    let reg_roots = [
        (HKEY_CURRENT_USER, "HKCU", r"Software"),
        (HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE"),
        (HKEY_LOCAL_MACHINE, "HKLM", r"SYSTEM\CurrentControlSet\Services"),
    ];

    for (root, root_name, subkey) in reg_roots {
        scan_reg_recursive(root, root_name, subkey, 0, &mut snap);
    }

    snap
}

fn compare_snapshots(before: &SystemSnapshot, after: &SystemSnapshot) -> Vec<TrackedChange> {
    let mut changes = Vec::new();

    // Новые папки
    for dir in &after.dirs {
        if !before.dirs.contains(dir) {
            changes.push(TrackedChange {
                kind: ChangeKind::Added,
                target: TargetType::Directory,
                path: dir.clone(),
                details: "Создана новая директория".to_string(),
            });
        }
    }

    // Новые и измененные файлы
    for (path, &(size_after, mtime_after)) in &after.files {
        match before.files.get(path) {
            None => {
                changes.push(TrackedChange {
                    kind: ChangeKind::Added,
                    target: TargetType::File,
                    path: path.clone(),
                    details: format!("Размер: {} байт", size_after),
                });
            }
            Some(&(size_before, mtime_before)) => {
                if size_before != size_after || mtime_before != mtime_after {
                    changes.push(TrackedChange {
                        kind: ChangeKind::Modified,
                        target: TargetType::File,
                        path: path.clone(),
                        details: format!("Размер: {} -> {} байт", size_before, size_after),
                    });
                }
            }
        }
    }

    // Новые разделы реестра
    for key in after.reg_keys.keys() {
        if !before.reg_keys.contains_key(key) {
            changes.push(TrackedChange {
                kind: ChangeKind::Added,
                target: TargetType::RegistryKey,
                path: key.clone(),
                details: "Создан раздел реестра".to_string(),
            });
        }
    }

    // Новые и измененные параметры реестра
    for (val_path, val_after) in &after.reg_values {
        match before.reg_values.get(val_path) {
            None => {
                changes.push(TrackedChange {
                    kind: ChangeKind::Added,
                    target: TargetType::RegistryValue,
                    path: val_path.clone(),
                    details: format!("Значение: {}", val_after),
                });
            }
            Some(val_before) => {
                if val_before != val_after {
                    changes.push(TrackedChange {
                        kind: ChangeKind::Modified,
                        target: TargetType::RegistryValue,
                        path: val_path.clone(),
                        details: format!("Было: {} -> Стало: {}", val_before, val_after),
                    });
                }
            }
        }
    }

    changes.sort_by(|a, b| a.target.cmp(&b.target).then_with(|| a.path.cmp(&b.path)));
    changes
}

enum ScanTask {
    BeforeDone(SystemSnapshot),
    AfterDone(Vec<TrackedChange>),
}

#[derive(PartialEq, Eq)]
enum TrackerState {
    Idle,
    ScanningBefore,
    WaitingForInstall,
    ScanningAfter,
    Finished,
}

struct InstallTrackerApp {
    state: TrackerState,
    before_snap: Option<SystemSnapshot>,
    changes: Vec<TrackedChange>,
    rx: Option<Receiver<ScanTask>>,
    filter_text: String,
    show_files: bool,
    show_registry: bool,
    only_added: bool,
    status_msg: String,
}

impl InstallTrackerApp {
    fn new() -> Self {
        Self {
            state: TrackerState::Idle,
            before_snap: None,
            changes: Vec::new(),
            rx: None,
            filter_text: String::new(),
            show_files: true,
            show_registry: true,
            only_added: false,
            status_msg: "Шаг 1: Нажми «Снять снимок ДО установки», затем запусти установщик.".into(),
        }
    }

    fn start_before_scan(&mut self) {
        self.state = TrackerState::ScanningBefore;
        self.changes.clear();
        self.status_msg = "Сканирование файлов и реестра ДО установки (подожди 5–15 сек)...".into();

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        thread::spawn(move || {
            let snap = take_snapshot();
            let _ = tx.send(ScanTask::BeforeDone(snap));
        });
    }

    fn start_after_scan(&mut self) {
        let Some(before) = self.before_snap.take() else {
            return;
        };
        self.state = TrackerState::ScanningAfter;
        self.status_msg = "Сканирование ПОСЛЕ установки и поиск различий...".into();

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        thread::spawn(move || {
            let after = take_snapshot();
            let diff = compare_snapshots(&before, &after);
            let _ = tx.send(ScanTask::AfterDone(diff));
        });
    }

    fn export_report(&mut self) {
        let mut out = String::new();
        out.push_str("=== ОТЧЕТ INSTALL TRACKER ===\n");
        out.push_str(&format!("Всего зафиксировано изменений: {}\n\n", self.changes.len()));

        for c in &self.changes {
            out.push_str(&format!(
                "{} [{}] {}\n    {}\n",
                c.kind.label(),
                c.target.label(),
                c.path,
                c.details
            ));
        }

        let report_path = PathBuf::from("install_trace_report.txt");
        match fs::write(&report_path, out) {
            Ok(()) => {
                self.status_msg = format!(
                    "Отчет сохранен рядом с программой: {}",
                    report_path.display()
                );
            }
            Err(e) => {
                self.status_msg = format!("Ошибка сохранения отчета: {}", e);
            }
        }
    }
}

impl eframe::App for InstallTrackerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Проверяем завершение фонового потока сканирования
        if let Some(rx) = &self.rx {
            if let Ok(msg) = rx.try_recv() {
                match msg {
                    ScanTask::BeforeDone(snap) => {
                        let f_cnt = snap.files.len();
                        let r_cnt = snap.reg_values.len();
                        self.before_snap = Some(snap);
                        self.state = TrackerState::WaitingForInstall;
                        self.status_msg = format!(
                            "Снимок ДО готов (файлов: {}, параметров реестра: {}). Теперь установи программу и нажми «Завершить отслеживание».",
                            f_cnt, r_cnt
                        );
                    }
                    ScanTask::AfterDone(diff) => {
                        let count = diff.len();
                        self.changes = diff;
                        self.state = TrackerState::Finished;
                        self.status_msg =
                            format!("Отслеживание завершено! Найдено изменений: {}", count);
                    }
                }
                self.rx = None;
            }
        }

        if self.state == TrackerState::ScanningBefore || self.state == TrackerState::ScanningAfter {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("top_controls").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                match self.state {
                    TrackerState::Idle | TrackerState::Finished => {
                        if ui.button("▶ 1. Снять снимок ДО установки").clicked() {
                            self.start_before_scan();
                        }
                    }
                    TrackerState::ScanningBefore | TrackerState::ScanningAfter => {
                        ui.spinner();
                        ui.label("Идет сканирование системы...");
                    }
                    TrackerState::WaitingForInstall => {
                        if ui
                            .button(
                                egui::RichText::new("⏹ 2. Завершить отслеживание (Снимок ПОСЛЕ)")
                                    .strong()
                                    .color(egui::Color32::from_rgb(100, 220, 120)),
                            )
                            .clicked()
                        {
                            self.start_after_scan();
                        }
                    }
                }

                if self.state == TrackerState::Finished && !self.changes.is_empty() {
                    ui.separator();
                    if ui.button("💾 Сохранить отчет (.txt)").clicked() {
                        self.export_report();
                    }
                }
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Фильтр:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter_text)
                        .hint_text("Имя папки, файла или ключа реестра...")
                        .desired_width(250.0),
                );
                if ui.button("✖").clicked() {
                    self.filter_text.clear();
                }

                ui.separator();
                ui.checkbox(&mut self.show_files, "Файлы и папки");
                ui.checkbox(&mut self.show_registry, "Реестр");
                ui.checkbox(&mut self.only_added, "Только добавленные (+)");
            });
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("status_panel").show(ctx, |ui| {
            ui.label(&self.status_msg);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.changes.is_empty() {
                ui.centered_and_justified(|ui| {
                    let hint = match self.state {
                        TrackerState::Idle => "Нажми «Снять снимок ДО установки» в верхней панели, чтобы зафиксировать состояние системы.",
                        TrackerState::ScanningBefore => "Собираем базовый слепок файлов и реестра...",
                        TrackerState::WaitingForInstall => "Монитор готов! Установи нужную программу или выполни действия в системе, затем нажми «Завершить отслеживание».",
                        TrackerState::ScanningAfter => "Сравниваем состояние системы...",
                        TrackerState::Finished => "Изменений не обнаружено.",
                    };
                    ui.label(egui::RichText::new(hint).size(15.0).weak());
                });
                return;
            }

            let query = self.filter_text.to_lowercase();

            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new("changes_grid")
                        .striped(true)
                        .min_col_width(40.0)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            ui.strong("Действие");
                            ui.strong("Тип");
                            ui.strong("Путь в системе / реестре");
                            ui.strong("Подробности");
                            ui.end_row();

                            for c in &self.changes {
                                if self.only_added && c.kind != ChangeKind::Added {
                                    continue;
                                }
                                let is_fs = matches!(
                                    c.target,
                                    TargetType::File | TargetType::Directory
                                );
                                if is_fs && !self.show_files {
                                    continue;
                                }
                                if !is_fs && !self.show_registry {
                                    continue;
                                }
                                if !query.is_empty()
                                    && !c.path.to_lowercase().contains(&query)
                                    && !c.details.to_lowercase().contains(&query)
                                {
                                    continue;
                                }

                                let color = match c.kind {
                                    ChangeKind::Added => egui::Color32::from_rgb(100, 215, 115),
                                    ChangeKind::Modified => egui::Color32::from_rgb(235, 190, 80),
                                };

                                ui.label(egui::RichText::new(c.kind.label()).color(color).strong());
                                ui.label(c.target.label());
                                ui.label(&c.path);
                                ui.label(egui::RichText::new(&c.details).weak());
                                ui.end_row();
                            }
                        });
                });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1150.0, 660.0])
            .with_title("Install Tracker RS"),
        ..Default::default()
    };

    eframe::run_native(
        "Install Tracker RS",
        options,
        Box::new(|_cc| Ok(Box::new(InstallTrackerApp::new()))),
    )
}