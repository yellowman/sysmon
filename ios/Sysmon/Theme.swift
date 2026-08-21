import SwiftUI
import UIKit

// The sysmon design language: ink on paper, editorial type, and status
// color used sparingly - green/amber/red are the only loud things on
// screen. Every color adapts to light/dark so the app looks deliberate
// in both. Mirrors android/ui/theme/Theme.kt.
enum Theme {
    // Canvas & ink
    static let paper = dyn(0xFAFAF7, 0x0E0E0E) // screen background
    static let surface = dyn(0xFFFFFF, 0x161616) // cards
    static let surfaceSubtle = dyn(0xF1EFE9, 0x1E1E1E) // inset fields
    static let ink = dyn(0x0A0A0A, 0xFAFAF7) // primary text, buttons
    static let onInk = dyn(0xFAFAF7, 0x0A0A0A) // text on ink buttons
    static let subtle = dyn(0x6B6B6B, 0xB5B5B5) // secondary text
    static let faint = dyn(0xA8A49C, 0x6E6E6E) // tertiary text, chevrons
    static let hairline = dyn(0xE4E2DC, 0x2A2A2A) // borders

    // Status - slightly brighter in dark mode so they read on near-black.
    static let up = dyn(0x1F8A3F, 0x4CC38A)
    static let down = dyn(0xC53030, 0xFF6369)
    static let warn = dyn(0xB58900, 0xE5C07B)
    static let neutral = dyn(0x8A8A8A, 0x9A9A9A) // paused / unknown

    private static func dyn(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(UIColor { trait in
            trait.userInterfaceStyle == .dark ? UIColor(rgb: dark) : UIColor(rgb: light)
        })
    }
}

private extension UIColor {
    convenience init(rgb: UInt32) {
        self.init(
            red: CGFloat((rgb >> 16) & 0xFF) / 255,
            green: CGFloat((rgb >> 8) & 0xFF) / 255,
            blue: CGFloat(rgb & 0xFF) / 255,
            alpha: 1
        )
    }
}

func statusColor(_ status: String) -> Color {
    switch status {
    case "OK": return Theme.up
    case "WARNING": return Theme.warn
    case "CRITICAL": return Theme.down
    default: return Theme.neutral
    }
}

// A card: surface on paper with a hairline stroke and a whisper of
// depth. The shadow is imperceptible in dark mode by design - the
// surface/paper contrast carries it there.
struct CardStyle: ViewModifier {
    var padding: CGFloat = 14
    func body(content: Content) -> some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.surface)
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Theme.hairline, lineWidth: 1))
            .cornerRadius(12)
            .shadow(color: Color.black.opacity(0.04), radius: 6, x: 0, y: 2)
    }
}

extension View {
    func card(padding: CGFloat = 14) -> some View {
        modifier(CardStyle(padding: padding))
    }
}

// The owning sysmond's name as a small muted capsule. Deliberately
// quiet - it is context, not the subject - and callers skip it entirely
// on a single-box install, where rows look exactly as they always did.
struct SiteTag: View {
    let name: String

    var body: some View {
        Text(name)
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(Theme.subtle)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(Capsule().fill(Theme.surfaceSubtle))
            .lineLimit(1)
    }
}

// Status dot with a soft glow halo; pulses when the status is CRITICAL
// so a down host is impossible to miss at a glance.
struct StatusDot: View {
    let status: String
    var pulse: Bool = false
    @State private var animating = false

    var body: some View {
        let color = statusColor(status)
        ZStack {
            if pulse {
                Circle()
                    .fill(color)
                    .frame(width: 8, height: 8)
                    .scaleEffect(animating ? 2.6 : 1.0)
                    .opacity(animating ? 0 : 0.55)
            }
            Circle()
                .fill(color.opacity(0.18))
                .frame(width: 16, height: 16)
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
        }
        .frame(width: 16, height: 16)
        .onAppear {
            guard pulse else { return }
            withAnimation(.easeOut(duration: 1.4).repeatForever(autoreverses: false)) {
                animating = true
            }
        }
    }
}

// Tiny heartbeat indicator for the nav bar: the visible face of the
// live delta poller. Green + pulsing while updates flow, amber when the
// last poll failed (OFFLINE) or when polling works but no sysmond is
// reporting to the server (DEGRADED).
struct LivePill: View {
    let offline: Bool
    var degraded: Bool = false
    @State private var animating = false

    private var alarmed: Bool { offline || degraded }

    var body: some View {
        HStack(spacing: 5) {
            Circle()
                .fill(alarmed ? Theme.warn : Theme.up)
                .frame(width: 6, height: 6)
                .opacity(alarmed ? 1 : (animating ? 0.25 : 1))
            Text(offline ? "OFFLINE" : (degraded ? "DEGRADED" : "LIVE"))
                .font(.system(size: 9, weight: .bold))
                .tracking(1.2)
                .foregroundColor(alarmed ? Theme.warn : Theme.subtle)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Capsule().fill(Theme.surfaceSubtle))
        .overlay(Capsule().stroke(Theme.hairline, lineWidth: 1))
        .onAppear {
            withAnimation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true)) {
                animating = true
            }
        }
    }
}

// Full-width primary action in the house style: ink slab, tracked-out
// caps, paper text.
struct SlabButtonStyle: ButtonStyle {
    var enabled: Bool = true
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .semibold))
            .tracking(1.2)
            .foregroundColor(Theme.onInk)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 13)
            .background(enabled ? Theme.ink : Theme.faint.opacity(0.4))
            .cornerRadius(10)
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .opacity(configuration.isPressed ? 0.85 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}
