using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Effects;

namespace HackerFirewall.Controls
{
    public class GlowBorder : Border
    {
        public GlowBorder()
        {
            BorderBrush = new SolidColorBrush(Color.FromRgb(0, 85, 26));
            BorderThickness = new Thickness(1);
            Background = new SolidColorBrush(Color.FromArgb(200, 10, 15, 20));
            Padding = new Thickness(8);
            Margin = new Thickness(4);
            CornerRadius = new CornerRadius(0);

            Effect = new DropShadowEffect
            {
                Color = Color.FromRgb(0, 255, 0),
                BlurRadius = 15,
                ShadowDepth = 0,
                Opacity = 0.2
            };
        }
    }
}
