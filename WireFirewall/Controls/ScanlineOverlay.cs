using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace HackerFirewall.Controls
{
    public class ScanlineOverlay : Grid
    {
        public ScanlineOverlay()
        {
            IsHitTestVisible = false;

            // Scanline rectangle
            var scanlines = new Rectangle
            {
                Fill = (Brush)Application.Current.FindResource("ScanlineBrush"),
                Opacity = 0.06,
                IsHitTestVisible = false
            };

            // CRT vignette
            var vignette = new Rectangle
            {
                Fill = (Brush)Application.Current.FindResource("VignetteBrush"),
                IsHitTestVisible = false
            };

            Children.Add(scanlines);
            Children.Add(vignette);
        }
    }
}
