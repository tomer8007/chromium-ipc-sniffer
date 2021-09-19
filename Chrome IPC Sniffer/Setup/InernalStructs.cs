using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ChromiumIPCSniffer.Mojo
{
    public class InernalStructs
    {
        //
        // The structure of each validation info entry is:
        // <uint64> name                                    (the key)
        // <uint64> request validator function pointer
        // <uint64> response validator function pointer
        // https://source.chromium.org/chromium/chromium/src/+/main:mojo/public/cpp/bindings/lib/generated_code_util.h;drc=3095f0ce2cadab0ffa2d0ae922ad7dffd3eeda30;l=20
        //

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ValidationTableEntry
        {
            public UInt64 name;                     // the key as uint32_t, aligned to 64 bit
            public UInt64 requestValidator;
            public UInt64 responseValidator;

            public bool LooksCorrect()
            {
                return 40000 < name && name < UInt32.MaxValue && requestValidator > 0x100400000 && requestValidator < 0x200000000;
            }
        };
    }
}
