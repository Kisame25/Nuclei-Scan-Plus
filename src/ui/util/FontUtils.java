package ui.util;

import javax.swing.*;
import java.awt.*;

public class FontUtils {
    // Standard UI Font (Labels, Buttons)
    public static Font getStandardFont() {
        Font font = UIManager.getFont("Label.font");
        return font != null ? font : new Font("SansSerif", Font.PLAIN, 12);
    }

    // Monospaced Font (Requests, Responses, Logs)
    public static Font getCodeFont() {
        Font font = UIManager.getFont("TextArea.font");
        return font != null ? font : new Font("Monospaced", Font.PLAIN, 12);
    }

    public static Font getHeadingFont() {
        Font base = getStandardFont();
        return base.deriveFont(Font.BOLD, base.getSize2D() + 2.0f);
    }
    // Bold title font based on user settings
    public static Font getTitleFont() {
        Font base = getStandardFont();
        return base.deriveFont(Font.BOLD, base.getSize2D());
    }

    public static Font getSubTitleFont() {
        Font base = getStandardFont();
        return base.deriveFont(Font.PLAIN, base.getSize2D() - 1.0f);
    }

    public static Font getSmallFont() {
        Font base = getStandardFont();
        return base.deriveFont(Font.BOLD, base.getSize2D() - 2.0f);
    }
}
