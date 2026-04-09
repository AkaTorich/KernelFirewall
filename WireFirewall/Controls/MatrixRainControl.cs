using System;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace HackerFirewall.Controls
{
    public class MatrixRainControl : Image
    {
        private DispatcherTimer _timer;
        private readonly Random _rng = new Random();
        private int[] _drops;
        private char[] _chars;
        private int _columns;
        private int _rows;
        private int _pixelW, _pixelH;
        private WriteableBitmap _bitmap;
        private const int CellW = 10;
        private const int CellH = 14;

        private static readonly string CharSet = "0123456789ABCDEF@#$%&*=+/<>[]{}";

        // Pre-baked green shades (BGRA)
        private static readonly uint[] TrailColors;

        static MatrixRainControl()
        {
            // 8 trail shades from bright to dim
            TrailColors = new uint[8];
            for (int i = 0; i < 8; i++)
            {
                byte g = (byte)(200 - i * 24);
                byte a = (byte)(100 - i * 10);
                TrailColors[i] = (uint)((a << 24) | (g << 8)); // ARGB -> green channel
            }
        }

        public MatrixRainControl()
        {
            IsHitTestVisible = false;
            Stretch = System.Windows.Media.Stretch.Fill;
            Loaded += OnLoaded;
            Unloaded += OnUnloaded;
            SizeChanged += (s, e) => RebuildBitmap();
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            RebuildBitmap();
            _timer = new DispatcherTimer(DispatcherPriority.Render)
            {
                Interval = TimeSpan.FromMilliseconds(100)
            };
            _timer.Tick += OnTick;
            _timer.Start();
        }

        private void OnUnloaded(object sender, RoutedEventArgs e)
        {
            _timer?.Stop();
        }

        private void RebuildBitmap()
        {
            _pixelW = (int)ActualWidth;
            _pixelH = (int)ActualHeight;
            if (_pixelW < 1 || _pixelH < 1) return;

            _columns = _pixelW / CellW;
            _rows = _pixelH / CellH;
            if (_columns < 1 || _rows < 1) return;

            _drops = new int[_columns];
            _chars = new char[_columns];
            for (int i = 0; i < _columns; i++)
            {
                _drops[i] = _rng.Next(-_rows, 0);
                _chars[i] = CharSet[_rng.Next(CharSet.Length)];
            }

            _bitmap = new WriteableBitmap(_columns, _rows, 96, 96, PixelFormats.Bgra32, null);
            Source = _bitmap;
        }

        private void OnTick(object sender, EventArgs e)
        {
            if (_bitmap == null || _drops == null) return;

            _bitmap.Lock();
            try
            {
                unsafe
                {
                    var buf = (uint*)_bitmap.BackBuffer;
                    int stride = _bitmap.BackBufferStride / 4;

                    // Fade existing pixels
                    for (int y = 0; y < _rows; y++)
                    {
                        for (int x = 0; x < _columns; x++)
                        {
                            ref uint pixel = ref buf[y * stride + x];
                            if (pixel != 0)
                            {
                                uint a = (pixel >> 24) & 0xFF;
                                uint g = (pixel >> 8) & 0xFF;
                                a = a > 15 ? a - 15 : 0;
                                g = g > 20 ? g - 20 : 0;
                                pixel = (a << 24) | (g << 8);
                            }
                        }
                    }

                    // Draw new drops
                    for (int col = 0; col < _columns; col++)
                    {
                        _drops[col]++;

                        int head = _drops[col];
                        if (head >= 0 && head < _rows)
                        {
                            // Bright head
                            buf[head * stride + col] = 0x80C8FF00; // bright green-white head
                        }

                        // Trail
                        for (int t = 1; t < 6 && head - t >= 0 && head - t < _rows; t++)
                        {
                            ref uint px = ref buf[(head - t) * stride + col];
                            uint g = (uint)(140 - t * 20);
                            uint a = (uint)(80 - t * 10);
                            uint val = (a << 24) | (g << 8);
                            if (px < val) px = val;
                        }

                        if (_drops[col] > _rows + _rng.Next(5, 25))
                        {
                            _drops[col] = _rng.Next(-15, -1);
                        }
                    }
                }

                _bitmap.AddDirtyRect(new Int32Rect(0, 0, _columns, _rows));
            }
            finally
            {
                _bitmap.Unlock();
            }
        }
    }
}
