use std::time::Instant;

use ratatui::style::Color;

pub fn reduced_motion() -> bool {
    std::env::var_os("NO_COLOR").is_some()
        || env_flag("SYSDAG_REDUCED_MOTION")
        || std::env::var_os("SSH_CONNECTION").is_some()
}

fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => !matches!(v.as_str(), "" | "0" | "false" | "off"),
        Err(_) => false,
    }
}

#[derive(Clone, Debug)]
pub struct Spring {
    pub pos: f32,
    pub vel: f32,
    pub target: f32,
}

impl Spring {
    pub fn new(value: f32) -> Self {
        Self {
            pos: value,
            vel: 0.0,
            target: value,
        }
    }

    pub fn set(&mut self, target: f32) {
        self.target = target;
    }

    pub fn snap(&mut self, value: f32) {
        self.pos = value;
        self.target = value;
        self.vel = 0.0;
    }

    pub fn step(&mut self, dt: f32) {
        let dt = dt.clamp(0.0, 0.048);
        let stiffness = 210.0;
        let damping = 26.0;
        let acc = -stiffness * (self.pos - self.target) - damping * self.vel;
        self.vel += acc * dt;
        self.pos += self.vel * dt;
        if self.settled() {
            self.pos = self.target;
            self.vel = 0.0;
        }
    }

    pub fn settled(&self) -> bool {
        (self.pos - self.target).abs() < 0.003 && self.vel.abs() < 0.02
    }
}

pub fn ease_out(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t) * (1.0 - t)
}

pub fn lerp_u8(a: u8, b: u8, t: f32) -> u8 {
    let t = t.clamp(0.0, 1.0);
    (a as f32 + (b as f32 - a as f32) * t).round() as u8
}

pub fn lerp_color(a: Color, b: Color, t: f32) -> Color {
    match (rgb(a), rgb(b)) {
        (Some((ar, ag, ab)), Some((br, bg, bb))) => {
            Color::Rgb(lerp_u8(ar, br, t), lerp_u8(ag, bg, t), lerp_u8(ab, bb, t))
        }
        _ => {
            if t < 0.5 {
                a
            } else {
                b
            }
        }
    }
}

fn rgb(c: Color) -> Option<(u8, u8, u8)> {
    match c {
        Color::Rgb(r, g, b) => Some((r, g, b)),
        _ => None,
    }
}

pub fn hsl(h: f32, s: f32, l: f32) -> Color {
    let h = ((h % 360.0) + 360.0) % 360.0 / 360.0;
    let s = s.clamp(0.0, 1.0);
    let l = l.clamp(0.0, 1.0);
    let a = s * l.min(1.0 - l);
    let f = |n: f32| {
        let k = (n + h * 12.0) % 12.0;
        l - a * (k - 3.0).min(9.0 - k).clamp(-1.0, 1.0)
    };
    Color::Rgb(
        (f(0.0) * 255.0).round() as u8,
        (f(8.0) * 255.0).round() as u8,
        (f(4.0) * 255.0).round() as u8,
    )
}

const SCRAMBLE: &[char] = &[
    '░', '▒', '▓', '/', '<', '>', '-', '+', '|', ':', '*', '#', '%', '@', '?',
];

/// Fixed-width decrypt. Cell count never changes.
pub fn decrypt(target: &str, width: usize, t: f32) -> String {
    let mut out = String::new();
    let chars: Vec<char> = target.chars().collect();
    let t = t.clamp(0.0, 1.0);
    for i in 0..width {
        let reveal = t * width as f32 - i as f32 * 0.55;
        if reveal >= 1.0 {
            out.push(chars.get(i).copied().unwrap_or(' '));
        } else {
            let idx = (i.wrapping_mul(11) + (t * 47.0) as usize) % SCRAMBLE.len();
            out.push(SCRAMBLE[idx]);
        }
    }
    out
}

pub fn pad_cells(text: &str, width: usize) -> String {
    let mut out: String = text.chars().take(width).collect();
    while out.chars().count() < width {
        out.push(' ');
    }
    out
}

const BLOCKS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

pub fn sparkline(values: &[f64], width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if values.is_empty() {
        return "▁".repeat(width);
    }
    let max = values.iter().copied().fold(0.05_f64, f64::max);
    let mut out = String::new();
    for i in 0..width {
        let src = if values.len() == 1 {
            values[0]
        } else {
            let t = i as f64 / (width - 1).max(1) as f64;
            let idx = (t * (values.len() - 1) as f64).round() as usize;
            values[idx.min(values.len() - 1)]
        };
        let n = ((src / max) * (BLOCKS.len() - 1) as f64).round() as usize;
        out.push(BLOCKS[n.min(BLOCKS.len() - 1)]);
    }
    out
}

const BRAILLE: &[char] = &[
    '⠁', '⠂', '⠄', '⠈', '⠐', '⠠', '⡀', '⢀', '⠃', '⠉', '⠊', '⠒', '⠤', '⠙', '⣿', '✶',
];

pub fn burst_cells(seed: u64, t: f32, width: usize) -> String {
    let t = t.clamp(0.0, 1.0);
    let mut out = String::new();
    for i in 0..width {
        if t > 0.82 {
            out.push(' ');
            continue;
        }
        let n = seed
            .wrapping_add(i as u64)
            .wrapping_mul(6364136223846793005);
        let idx = ((n >> 8) as usize + (t * 19.0) as usize) % (BRAILLE.len() - 1);
        // Keep one reserved rare star; last glyph is decorative only.
        let ch = if n.is_multiple_of(11) {
            BRAILLE[BRAILLE.len() - 1]
        } else {
            BRAILLE[idx]
        };
        out.push(ch);
    }
    out
}

pub fn elapsed_frac(start: Instant, dur_ms: u64) -> f32 {
    start.elapsed().as_secs_f32() / (dur_ms as f32 / 1000.0)
}
