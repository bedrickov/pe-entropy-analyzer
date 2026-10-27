using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace PEGuard;

public class PeParser
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ImageDosHeader
    {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }

    public struct SectionInfo
    {
        public string Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint RawSize;
        public uint Characteristics;
        public double Entropy;
    }

    public static double CalculateEntropy(byte[] data, int offset, int length)
    {
        if (length <= 0) return 0.0;
        int[] freq = new int[256];
        for (int i = offset; i < offset + length && i < data.Length; i++)
        {
            freq[data[i]]++;
        }

        double entropy = 0.0;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] > 0)
            {
                double p = (double)freq[i] / length;
                entropy -= p * Math.Log2(p);
            }
        }
        return entropy;
    }

    public static List<SectionInfo> ParseSections(string filePath)
    {
        var sections = new List<SectionInfo>();
        byte[] bytes = File.ReadAllBytes(filePath);
        if (bytes.Length < 64) return sections;

        if (bytes[0] != 0x4D || bytes[1] != 0x5A) // 'MZ'
            throw new InvalidDataException("Invalid DOS signature");

        int peOffset = BitConverter.ToInt32(bytes, 0x3C);
        if (peOffset + 4 > bytes.Length) return sections;

        if (bytes[peOffset] != 0x50 || bytes[peOffset + 1] != 0x45) // 'PE\0\0'
            throw new InvalidDataException("Invalid NT PE signature");

        ushort numSections = BitConverter.ToUInt16(bytes, peOffset + 6);
        ushort optHeaderSize = BitConverter.ToUInt16(bytes, peOffset + 20);

        int sectionTableOffset = peOffset + 24 + optHeaderSize;

        for (int i = 0; i < numSections; i++)
        {
            int cur = sectionTableOffset + (i * 40);
            if (cur + 40 > bytes.Length) break;

            string name = Encoding.ASCII.GetString(bytes, cur, 8).TrimEnd('\0');
            uint vSize = BitConverter.ToUInt32(bytes, cur + 8);
            uint vAddr = BitConverter.ToUInt32(bytes, cur + 12);
            uint rawSize = BitConverter.ToUInt32(bytes, cur + 16);
            uint rawPtr = BitConverter.ToUInt32(bytes, cur + 20);
            uint chars = BitConverter.ToUInt32(bytes, cur + 36);

            double entropy = CalculateEntropy(bytes, (int)rawPtr, (int)rawSize);

            sections.Add(new SectionInfo
            {
                Name = name,
                VirtualSize = vSize,
                VirtualAddress = vAddr,
                RawSize = rawSize,
                Characteristics = chars,
                Entropy = entropy
            });
        }

        return sections;
    }
}

class Program
{
    static int Main(string[] args)
    {
        Console.WriteLine("[PEGuard] High-Performance PE Header & Section Entropy Verifier");

        string target = args.Length > 0 ? args[0] : Environment.ProcessPath!;
        Console.WriteLine($"Analyzing PE Binary: {target}\n");

        if (!File.Exists(target))
        {
            Console.WriteLine("File not found.");
            return 1;
        }

        try
        {
            var sections = PeParser.ParseSections(target);
            Console.WriteLine($"{"SECTION",-12} {"VIRT_SIZE",-12} {"RAW_SIZE",-12} {"ENTROPY",-10} {"STATUS"}");
            Console.WriteLine(new string('-', 60));

            foreach (var s in sections)
            {
                string status = s.Entropy > 7.2 ? "PACKED/ENCRYPTED" : "NORMAL";
                Console.WriteLine($"{s.Name,-12} 0x{s.VirtualSize,-10:X} 0x{s.RawSize,-10:X} {s.Entropy,-10:F3} {status}");
            }

            Console.WriteLine($"\nSuccessfully parsed {sections.Count} sections.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error analyzing PE: {ex.Message}");
            return 2;
        }
    }
}
